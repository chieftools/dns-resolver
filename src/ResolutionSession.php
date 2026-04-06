<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver;

use Closure;
use RuntimeException;
use ChiefTools\DNS\Resolver\Data\RootServers;
use ChiefTools\DNS\Resolver\Events\EventType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Dnssec\DnssecValidator;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Dnssec\WireFormatConverter;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;

/**
 * @internal Single-use resolution session. Use Resolver as the public API.
 */
class ResolutionSession
{
    private ?DnssecValidator $dnssecValidator;

    /** @var (Closure(ResolverEvent): void)|null */
    private ?Closure $onEvent;

    private int $totalTimeMs = 0;

    public function __construct(
        private readonly DnsQueryExecutor $executor,
        private readonly ResolverConfig $config,
        ?DnssecValidator $dnssecValidator = null,
        ?Closure $onEvent = null,
    ) {
        $this->dnssecValidator = $dnssecValidator;
        $this->onEvent         = $onEvent;
    }

    public function getTotalTimeMs(): int
    {
        return $this->totalTimeMs;
    }

    public function getDnssecValidator(): ?DnssecValidator
    {
        return $this->dnssecValidator;
    }

    /**
     * Recursively resolve DNS records by traversing the delegation chain.
     *
     * @param list<string>                                                                    $types
     * @param list<array{host: string, addr: ?string, glue?: bool}>                           $nameservers
     * @param list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>|null $parentDs
     *
     * @return list<RawRecord>|string|null Returns records, 'NXDOMAIN', 'QUERY_FAILED', or null for empty
     */
    public function resolve(
        string $domain,
        array $types,
        array $nameservers,
        int $lookups = 0,
        int $depth = 0,
        ?array $parentDs = null,
        ?string $currentZone = null,
    ): array|string|null {
        if ($lookups > $this->config->maxDepth) {
            throw new RuntimeException('Too many recursive lookups!');
        }

        if (empty($nameservers) || empty($types)) {
            return null;
        }

        $domain      = rtrim($domain, '.');
        $primaryType = $types[0];
        $currentZone = $currentZone ?? '.';

        // Resolve nameserver address if needed
        $resolvedNameservers = $this->resolveNameserverAddress($nameservers, $domain, $types, $lookups, $depth, $parentDs, $currentZone);

        if ($resolvedNameservers === null) {
            return null;
        }

        $nameservers = $resolvedNameservers;
        $nameserver  = $nameservers[0];

        // DNSSEC: Validate zone DNSKEY
        $this->validateZoneDnssec($currentZone, $nameserver['addr'], $parentDs);

        // Query for the primary type
        $this->emit(new ResolverEvent(
            type: EventType::LOOKUP,
            message: "Lookup record for {$domain} @ {$nameserver['host']}" . (!empty($nameserver['glue']) ? ' [glue]' : '') . '...',
            depth: $depth,
            domain: $domain,
            nameserver: $nameserver['host'],
            address: $nameserver['addr'],
            glue: !empty($nameserver['glue']),
        ));

        try {
            $result = $this->query($domain, $primaryType, $nameserver['addr'], $this->dnssecValidator !== null);
        } catch (QueryException $e) {
            return $this->handleQueryFailure($domain, $types, $nameservers, $lookups, $depth, $parentDs, $currentZone, $e->getMessage());
        }

        $this->totalTimeMs += $result->queryTimeMs;

        if ($result->responseCode === 'NXDOMAIN') {
            return 'NXDOMAIN';
        }

        // Handle answers if present
        if ($result->answer !== []) {
            return $this->handleAnswers($result, $domain, $types, $nameserver, $currentZone, $lookups, $depth);
        }

        // Check for NS delegation
        $authorityNs = array_values(array_filter($result->authority, static fn (RawRecord $r) => $r->type === 'NS'));

        if ($authorityNs !== []) {
            return $this->handleDelegation($result, $domain, $types, $authorityNs, $nameserver, $currentZone, $lookups, $depth);
        }

        // No answers and no delegation - authoritative empty response
        return $this->handleEmptyResponse($result, $domain, $types, $nameserver, $currentZone, $depth);
    }

    /**
     * @param list<array{host: string, addr: ?string, glue?: bool}>                           $nameservers
     * @param list<string>                                                                    $types
     * @param list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>|null $parentDs
     *
     * @return list<array{host: string, addr: string, glue?: bool}>|null
     */
    private function resolveNameserverAddress(
        array $nameservers,
        string $domain,
        array $types,
        int $lookups,
        int $depth,
        ?array $parentDs,
        string $currentZone,
    ): ?array {
        if ($nameservers[0]['addr'] !== null) {
            /** @var list<array{host: string, addr: string, glue?: bool}> */
            return $nameservers;
        }

        $this->emit(new ResolverEvent(
            type: EventType::RESOLVE_NAMESERVER,
            message: "Resolving {$nameservers[0]['host']}...",
            depth: $depth,
            nameserver: $nameservers[0]['host'],
        ));

        $recurseLookupTypes = $this->getAllowedRecursiveLookupTypes();
        shuffle($recurseLookupTypes);

        // Use separate validator for nameserver resolution
        $savedValidator        = $this->dnssecValidator;
        $this->dnssecValidator = $savedValidator !== null ? new DnssecValidator : null;

        $lookupResult = null;

        foreach ($recurseLookupTypes as $recurseLookupType) {
            $nameserverLookupResult = $this->resolve(
                $nameservers[0]['host'],
                [$recurseLookupType],
                RootServers::random(ipv6: $this->config->ipv6),
                $lookups + 1,
                $depth + 1,
            );

            if (is_array($nameserverLookupResult)) {
                $allowedTypes = $this->getAllowedRecursiveLookupTypes();
                $filtered     = array_values(array_filter(
                    $nameserverLookupResult,
                    static fn (RawRecord $r) => in_array($r->type, $allowedTypes, true),
                ));

                if ($filtered !== []) {
                    $lookupResult = $filtered;
                    break;
                }
            }
        }

        $this->dnssecValidator = $savedValidator;

        if ($lookupResult === null) {
            $this->emit(new ResolverEvent(
                type: EventType::RESOLVE_FAILURE,
                message: "Failed to resolve {$nameservers[0]['host']} (no A/AAAA results)",
                depth: $depth,
                nameserver: $nameservers[0]['host'],
                reason: 'no A/AAAA results',
            ));

            if (count($nameservers) > 1) {
                $nextNameservers = array_slice($nameservers, 1);

                $this->emit(new ResolverEvent(
                    type: EventType::NAMESERVER_FALLBACK,
                    message: "Trying next nameserver: {$nextNameservers[0]['host']}...",
                    depth: $depth,
                    nameserver: $nextNameservers[0]['host'],
                ));

                return $this->resolveNameserverAddress($nextNameservers, $domain, $types, $lookups, $depth, $parentDs, $currentZone);
            }

            return null;
        }

        $selected               = $lookupResult[array_rand($lookupResult)];
        $nameservers[0]['addr'] = self::shortenIPv6($selected->data);

        /** @var list<array{host: string, addr: string, glue?: bool}> */
        return $nameservers;
    }

    /**
     * @param list<string>                                   $types
     * @param array{host: string, addr: string, glue?: bool} $nameserver
     *
     * @return list<RawRecord>
     */
    private function handleAnswers(
        QueryResult $result,
        string $domain,
        array $types,
        array $nameserver,
        string $currentZone,
        int $lookups,
        int $depth,
    ): array {
        $answers     = $result->answer;
        $primaryType = $types[0];

        // DNSSEC: Validate RRSIG on answers
        $validationStatus = $this->dnssecValidator !== null
            ? $this->validateAnswerRrsig($answers, $currentZone)
            : null;

        $this->emit(new ResolverEvent(
            type: EventType::QUERY,
            message: "Queried for {$primaryType} @ {$nameserver['addr']} in {$result->queryTimeMs}ms" . ($validationStatus !== null ? " ({$validationStatus})" : ''),
            depth: $depth,
            domain: $domain,
            recordType: $primaryType,
            address: $nameserver['addr'],
            timeMs: $result->queryTimeMs,
            status: $validationStatus,
        ));

        // Filter out RRSIG records from final answer
        $answers = array_values(array_filter($answers, static fn (RawRecord $r) => $r->type !== 'RRSIG'));

        // If only looking for CNAME records, return as-is
        if ($types === ['CNAME']) {
            return $this->deduplicateRecords($answers);
        }

        // Follow CNAME if present
        $cnameRecords = array_values(array_filter($answers, static fn (RawRecord $r) => $r->type === 'CNAME'));

        if ($cnameRecords !== []) {
            return $this->followCname($cnameRecords, $cnameRecords, $types, $lookups, $depth);
        }

        // Query for remaining types at the same authoritative nameserver
        $answers = $this->queryAdditionalTypes($answers, $domain, $types, $nameserver, $currentZone, $depth);

        return $this->deduplicateRecords($answers);
    }

    /**
     * @param list<RawRecord> $cnameRecords
     * @param list<RawRecord> $answers
     * @param list<string>    $types
     *
     * @return list<RawRecord>
     */
    private function followCname(array $cnameRecords, array $answers, array $types, int $lookups, int $depth): array
    {
        $typesToFollow = array_values(array_filter($types, static fn (string $t) => $t !== 'CNAME'));

        // Build a lookup map to follow the CNAME chain in order
        $cnameByName = [];

        foreach ($cnameRecords as $record) {
            $cnameByName[strtolower(rtrim($record->name, '.'))] = $record;
        }

        // Walk the chain starting from the first record, emitting events for each hop
        $cnameTarget = rtrim($cnameRecords[0]->data, '.');
        $seenTargets = [];

        while (true) {
            $normalizedTarget = strtolower($cnameTarget);

            if (isset($seenTargets[$normalizedTarget])) {
                return $this->deduplicateRecords($answers);
            }

            $seenTargets[$normalizedTarget] = true;

            // Don't follow CNAME targets that are not valid domain names
            if (!preg_match('/^([a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/', $cnameTarget)) {
                return $this->deduplicateRecords($answers);
            }

            $this->emit(new ResolverEvent(
                type: EventType::CNAME,
                message: "Following CNAME to {$cnameTarget}...",
                depth: $depth,
                domain: $cnameTarget,
            ));

            // If the target is another CNAME in the same response, continue the chain
            if (isset($cnameByName[$normalizedTarget])) {
                $cnameTarget = rtrim($cnameByName[$normalizedTarget]->data, '.');

                continue;
            }

            break;
        }

        $cnameResult = $this->resolve(
            $cnameTarget,
            $typesToFollow,
            RootServers::random(ipv6: $this->config->ipv6),
            $lookups + 1,
            $depth + 3,
        );

        if (is_array($cnameResult)) {
            $answers = array_merge($answers, $cnameResult);
        }

        return $this->deduplicateRecords($answers);
    }

    /**
     * @param list<RawRecord>                                $answers
     * @param list<string>                                   $types
     * @param array{host: string, addr: string, glue?: bool} $nameserver
     *
     * @return list<RawRecord>
     */
    private function queryAdditionalTypes(
        array $answers,
        string $domain,
        array $types,
        array $nameserver,
        string $currentZone,
        int $depth,
    ): array {
        foreach (array_slice($types, 1) as $additionalType) {
            try {
                $additionalResult = $this->query($domain, $additionalType, $nameserver['addr'], $this->dnssecValidator !== null);
            } catch (QueryException) {
                continue;
            }

            $this->totalTimeMs += $additionalResult->queryTimeMs;

            if ($additionalResult->answer !== []) {
                $additionalValidationStatus = $this->dnssecValidator !== null
                    ? $this->validateAnswerRrsig($additionalResult->answer, $currentZone)
                    : null;

                $this->emit(new ResolverEvent(
                    type: EventType::QUERY,
                    message: "Queried for {$additionalType} @ {$nameserver['addr']} in {$additionalResult->queryTimeMs}ms" . ($additionalValidationStatus !== null ? " ({$additionalValidationStatus})" : ''),
                    depth: $depth,
                    domain: $domain,
                    recordType: $additionalType,
                    address: $nameserver['addr'],
                    timeMs: $additionalResult->queryTimeMs,
                    status: $additionalValidationStatus,
                ));

                $additionalAnswers = array_values(array_filter($additionalResult->answer, static fn (RawRecord $r) => $r->type !== 'RRSIG'));
                $answers           = array_merge($answers, $additionalAnswers);
            } else {
                $emptyValidationStatus = $this->dnssecValidator !== null
                    ? $this->validateEmptyResponse($additionalResult->authority, $currentZone, $nameserver['addr'])
                    : null;

                $this->emit(new ResolverEvent(
                    type: EventType::QUERY,
                    message: "Queried for {$additionalType} @ {$nameserver['addr']} in {$additionalResult->queryTimeMs}ms" . ($emptyValidationStatus !== null ? " ({$emptyValidationStatus})" : ''),
                    depth: $depth,
                    domain: $domain,
                    recordType: $additionalType,
                    address: $nameserver['addr'],
                    timeMs: $additionalResult->queryTimeMs,
                    status: $emptyValidationStatus,
                ));
            }
        }

        return $answers;
    }

    /**
     * @param list<RawRecord>                                $authorityNs
     * @param array{host: string, addr: string, glue?: bool} $nameserver
     * @param list<string>                                   $types
     *
     * @return list<RawRecord>|string|null
     */
    private function handleDelegation(
        QueryResult $result,
        string $domain,
        array $types,
        array $authorityNs,
        array $nameserver,
        string $currentZone,
        int $lookups,
        int $depth,
    ): array|string|null {
        $primaryType   = $types[0];
        $delegatedZone = strtolower(rtrim($authorityNs[0]->name, '.'));

        // DNSSEC: Validate delegation
        [$nextDs, $delegationStatus] = $this->validateDelegation($result, $delegatedZone, $currentZone, $nameserver['addr']);

        $this->emit(new ResolverEvent(
            type: EventType::QUERY,
            message: "Queried for {$primaryType} @ {$nameserver['addr']} in {$result->queryTimeMs}ms" . ($delegationStatus !== null ? " ({$delegationStatus})" : ''),
            depth: $depth,
            domain: $domain,
            recordType: $primaryType,
            address: $nameserver['addr'],
            timeMs: $result->queryTimeMs,
            status: $delegationStatus,
        ));

        // Build next nameservers list
        $nextNameservers = $this->buildNextNameservers($result, $authorityNs);

        $this->emit(new ResolverEvent(
            type: EventType::DELEGATION,
            message: "Delegation to {$delegatedZone} via {$nextNameservers[0]['host']}...",
            depth: $depth,
            domain: $delegatedZone,
            nameserver: $nextNameservers[0]['host'],
        ));

        return $this->resolve($domain, $types, $nextNameservers, $lookups, $depth, $nextDs, $delegatedZone);
    }

    /**
     * @param list<RawRecord> $authorityNs
     *
     * @return list<array{host: string, addr: string|null, glue: bool}>
     */
    private function buildNextNameservers(QueryResult $result, array $authorityNs): array
    {
        $delegatedHosts = array_fill_keys(array_map(
            static fn (RawRecord $record): string => strtolower(rtrim($record->data, '.')),
            $authorityNs,
        ), true);

        $allowedTypes = $this->getAllowedRecursiveLookupTypes();

        $glueRecords = array_values(array_filter(
            $result->additional,
            static fn (RawRecord $r) => in_array($r->type, $allowedTypes, true) && isset($delegatedHosts[strtolower(rtrim($r->name, '.'))]),
        ));

        if ($glueRecords === []) {
            $nameservers = array_map(
                static fn (RawRecord $record) => ['host' => rtrim($record->data, '.'), 'addr' => null, 'glue' => false],
                $authorityNs,
            );
            shuffle($nameservers);

            return $nameservers;
        }

        $nameservers = array_map(
            static fn (RawRecord $record) => ['host' => rtrim($record->name, '.'), 'addr' => self::shortenIPv6($record->data), 'glue' => true],
            $glueRecords,
        );
        shuffle($nameservers);

        return $nameservers;
    }

    /**
     * @param array{host: string, addr: string, glue?: bool} $nameserver
     * @param list<string>                                   $types
     *
     * @return list<RawRecord>|null
     */
    private function handleEmptyResponse(
        QueryResult $result,
        string $domain,
        array $types,
        array $nameserver,
        string $currentZone,
        int $depth,
    ): ?array {
        $primaryType = $types[0];

        $emptyResponseStatus = $this->dnssecValidator !== null
            ? $this->validateEmptyResponse($result->authority, $currentZone, $nameserver['addr'])
            : null;

        $this->emit(new ResolverEvent(
            type: EventType::QUERY,
            message: "Queried for {$primaryType} @ {$nameserver['addr']} in {$result->queryTimeMs}ms" . ($emptyResponseStatus !== null ? " ({$emptyResponseStatus})" : ''),
            depth: $depth,
            domain: $domain,
            recordType: $primaryType,
            address: $nameserver['addr'],
            timeMs: $result->queryTimeMs,
            status: $emptyResponseStatus,
        ));

        // Query for remaining types at the same authoritative nameserver
        $answers = $this->queryAdditionalTypes([], $domain, $types, $nameserver, $currentZone, $depth);

        if ($answers === []) {
            return null;
        }

        return $this->deduplicateRecords($answers);
    }

    /**
     * @param list<array{host: string, addr: ?string, glue?: bool}>                           $nameservers
     * @param list<string>                                                                    $types
     * @param list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>|null $parentDs
     *
     * @return list<RawRecord>|string|null
     */
    private function handleQueryFailure(
        string $domain,
        array $types,
        array $nameservers,
        int $lookups,
        int $depth,
        ?array $parentDs,
        string $currentZone,
        string $reason = 'unknown error',
    ): array|string|null {
        $this->emit(new ResolverEvent(
            type: EventType::QUERY_FAILURE,
            message: "Failed to query {$nameservers[0]['addr']} ({$reason})",
            depth: $depth,
            address: $nameservers[0]['addr'],
            reason: $reason,
        ));

        if (count($nameservers) > 1) {
            $nextNameservers = array_slice($nameservers, 1);

            $this->emit(new ResolverEvent(
                type: EventType::NAMESERVER_FALLBACK,
                message: "Trying next nameserver: {$nextNameservers[0]['host']}...",
                depth: $depth,
                nameserver: $nextNameservers[0]['host'],
            ));

            return $this->resolve($domain, $types, $nextNameservers, $lookups, $depth, $parentDs, $currentZone);
        }

        return 'QUERY_FAILED';
    }

    /**
     * @param list<RawRecord> $records
     *
     * @return list<RawRecord>
     */
    private function deduplicateRecords(array $records): array
    {
        $seen   = [];
        $unique = [];

        foreach ($records as $record) {
            $key = $record->name . '|' . $record->type . '|' . $record->data;

            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[]   = $record;
            }
        }

        return $unique;
    }

    /**
     * @return list<string>
     */
    private function getAllowedRecursiveLookupTypes(): array
    {
        return $this->config->ipv6 ? ['A', 'AAAA'] : ['A'];
    }

    private function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        return $this->executor->query($domain, $type, $nameserverAddr, $dnssec);
    }

    private function emit(ResolverEvent $event): void
    {
        if ($this->onEvent !== null) {
            ($this->onEvent)($event);
        }
    }

    private static function shortenIPv6(string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        return inet_ntop($packed) ?: $ip;
    }

    // =========================================================================
    // DNSSEC validation methods
    // =========================================================================

    /**
     * @param list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>|null $parentDs
     */
    private function validateZoneDnssec(string $zone, string $nameserverAddr, ?array $parentDs): void
    {
        if ($this->dnssecValidator === null) {
            return;
        }

        if ($parentDs !== null) {
            $this->validateZoneDnskey($zone, $nameserverAddr, $parentDs);
        } elseif ($zone === '.') {
            $this->validateRootZoneDnskey($nameserverAddr);
        }
    }

    private function validateRootZoneDnskey(string $nameserverAddr): void
    {
        if ($this->dnssecValidator === null) {
            return;
        }

        $cached = $this->dnssecValidator->getCachedDnskeys('.');

        if ($cached !== null) {
            return;
        }

        try {
            $dnskeyResult = $this->query('.', 'DNSKEY', $nameserverAddr, true);
        } catch (QueryException) {
            // Transient network error — don't mark invalid so a fallback
            // nameserver can retry the DNSKEY fetch.
            return;
        }

        if ($dnskeyResult->answer === []) {
            $this->dnssecValidator->markInvalid('failed to fetch root DNSKEY');

            return;
        }

        $this->totalTimeMs += $dnskeyResult->queryTimeMs;

        $dnskeys = $this->parseDnskeysFromResult($dnskeyResult, '.');

        if (empty($dnskeys)) {
            $this->dnssecValidator->markInvalid('no valid DNSKEY records for root');

            return;
        }

        if (!$this->dnssecValidator->validateRootDnskeys($dnskeys)) {
            $this->dnssecValidator->markInvalid('root DNSKEY does not match trust anchor');

            return;
        }

        $this->dnssecValidator->cacheDnskeys('.', $dnskeys);
        $this->dnssecValidator->markSigned();
    }

    /**
     * @param list<array{keytag: int, algorithm: int, digest_type: int, digest: string}> $parentDs
     */
    private function validateZoneDnskey(string $zone, string $nameserverAddr, array $parentDs): void
    {
        if ($this->dnssecValidator === null) {
            return;
        }

        $cached = $this->dnssecValidator->getCachedDnskeys($zone);

        if ($cached !== null) {
            return;
        }

        try {
            $dnskeyResult = $this->query($zone, 'DNSKEY', $nameserverAddr, true);
        } catch (QueryException) {
            // Transient network error — don't mark the zone as invalid so a
            // fallback nameserver can retry the DNSKEY fetch.
            return;
        }

        if ($dnskeyResult->answer === []) {
            $this->dnssecValidator->markZoneInvalid($zone, "failed to fetch DNSKEY for {$zone}");

            return;
        }

        $this->totalTimeMs += $dnskeyResult->queryTimeMs;

        $dnskeys = $this->parseDnskeysFromResult($dnskeyResult, $zone);

        if (empty($dnskeys)) {
            $this->dnssecValidator->markZoneInvalid($zone, "no valid DNSKEY records for {$zone}");

            return;
        }

        $matchingKey = $this->dnssecValidator->findMatchingDnskey($parentDs, $dnskeys, $zone);

        if ($matchingKey === null) {
            $this->dnssecValidator->markZoneInvalid($zone, "no DNSKEY matches DS for {$zone}");

            return;
        }

        $dnskeyRrsig = null;

        foreach ($dnskeyResult->answer as $record) {
            if ($record->type === 'RRSIG') {
                $parsed = $this->dnssecValidator->parseRrsig($record->data);

                if ($parsed !== null && $parsed['type_covered'] === 'DNSKEY') {
                    $dnskeyRrsig = $parsed;

                    break;
                }
            }
        }

        if ($dnskeyRrsig === null) {
            $this->dnssecValidator->markZoneInvalid($zone, "DNSKEY for {$zone} is not signed");

            return;
        }

        $signingKey = $this->dnssecValidator->findSigningKey($dnskeyRrsig, $dnskeys);

        if ($signingKey === null) {
            $this->dnssecValidator->markZoneInvalid($zone, "no key found to verify DNSKEY RRSIG for {$zone}");

            return;
        }

        $dnskeyRrset = $this->toRawArrays(array_values(array_filter(
            $dnskeyResult->answer,
            static fn (RawRecord $r) => $r->type === 'DNSKEY',
        )));

        if (!$this->dnssecValidator->verifyRrsig($dnskeyRrsig, $dnskeyRrset, $signingKey)) {
            $this->dnssecValidator->markZoneInvalid($zone, "DNSKEY RRSIG verification failed for {$zone}");

            return;
        }

        $this->dnssecValidator->cacheDnskeys($zone, $dnskeys);
        $this->dnssecValidator->markSigned();
    }

    /**
     * @return array{0: list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>|null, 1: string|null}
     */
    private function validateDelegation(QueryResult $result, string $delegatedZone, string $currentZone, string $nameserverAddr): array
    {
        if ($this->dnssecValidator === null) {
            return [null, null];
        }

        $dsRecords = array_values(array_filter($result->authority, static fn (RawRecord $r) => $r->type === 'DS'));

        if ($dsRecords !== []) {
            $nextDs = array_values(array_filter(array_map(
                fn (RawRecord $r) => $this->dnssecValidator->parseDs($r->data),
                $dsRecords,
            )));

            if (!empty($nextDs)) {
                $dsRrsig = null;

                foreach ($result->authority as $r) {
                    if ($r->type === 'RRSIG' && str_starts_with($r->data, 'DS ')) {
                        $dsRrsig = $r;
                        break;
                    }
                }

                if ($dsRrsig !== null) {
                    $delegationStatus = $this->validateDsRrsig($dsRrsig, $dsRecords, $nameserverAddr) ?? 'unsigned';
                } else {
                    if ($this->dnssecValidator->getCachedDnskeys($currentZone) !== null) {
                        $this->dnssecValidator->markInvalid("DS records for {$delegatedZone} are not signed");
                        $delegationStatus = 'invalid';
                    } else {
                        $delegationStatus = 'unsigned';
                    }
                }

                return [$nextDs, $delegationStatus];
            }

            if ($this->dnssecValidator->getCachedDnskeys($currentZone) !== null) {
                $this->dnssecValidator->markInvalid("failed to parse DS records for {$delegatedZone}");

                return [null, 'invalid'];
            }

            return [null, 'unsigned'];
        }

        // No DS records - the parent must prove the child is unsigned.
        $delegationStatus = $this->validateNsecProofOfUnsigned($result->authority, $currentZone, $delegatedZone, $nameserverAddr);

        if ($delegationStatus === 'invalid') {
            return [null, 'invalid'];
        }

        $this->dnssecValidator->markUnsigned($delegatedZone);

        return [null, $delegationStatus];
    }

    /**
     * @param list<RawRecord> $dsRrsigRecords
     */
    private function validateDsRrsig(RawRecord $dsRrsigRecord, array $dsRrsigRecords, string $nameserverAddr): ?string
    {
        if ($this->dnssecValidator === null) {
            return null;
        }

        $rrsig = $this->dnssecValidator->parseRrsig($dsRrsigRecord->data);

        if ($rrsig === null) {
            $this->dnssecValidator->markInvalid('failed to parse DS RRSIG');

            return 'invalid';
        }

        $signerZone  = $rrsig['signer'];
        $zoneDnskeys = $this->dnssecValidator->getCachedDnskeys($signerZone);

        if ($zoneDnskeys === null) {
            if ($this->dnssecValidator->isZoneInvalid($signerZone)) {
                return 'invalid';
            }

            $zoneDnskeys = $this->fetchAndCacheDnskeys($signerZone, $nameserverAddr);

            if ($zoneDnskeys === null) {
                return null;
            }
        }

        $signingKey = $this->dnssecValidator->findSigningKey($rrsig, $zoneDnskeys);

        if ($signingKey === null) {
            $this->dnssecValidator->markInvalid("no key found to verify DS RRSIG from {$signerZone}");

            return 'invalid';
        }

        $dsRrset = $this->toRawArrays($dsRrsigRecords);

        if (!$this->dnssecValidator->verifyRrsig($rrsig, $dsRrset, $signingKey)) {
            $this->dnssecValidator->markInvalid("DS RRSIG verification failed from {$signerZone}");

            return 'invalid';
        }

        return 'signed';
    }

    /**
     * @param list<RawRecord> $answers
     */
    private function validateAnswerRrsig(array $answers, string $zone): ?string
    {
        if ($this->dnssecValidator === null) {
            return null;
        }

        $byRRset = [];
        $rrsigs  = [];

        // Group records by (name, type) to form proper RRsets — records with
        // different owner names are distinct RRsets even if they share a type
        // (e.g. chained CNAME records returned in the same response).
        foreach ($answers as $record) {
            if ($record->type === 'RRSIG') {
                $parsed = $this->dnssecValidator->parseRrsig($record->data);

                if ($parsed !== null) {
                    $rrsigs[$record->name . '|' . $parsed['type_covered']][] = $parsed;
                }
            } else {
                $byRRset[$record->name . '|' . $record->type][] = $record;
            }
        }

        if (empty($byRRset)) {
            return null;
        }

        $signerZone = null;

        foreach ($rrsigs as $typeRrsigs) {
            foreach ($typeRrsigs as $rrsig) {
                $signerZone = $rrsig['signer'];

                break 2;
            }
        }

        if ($signerZone === null) {
            $this->dnssecValidator->markUnsigned($zone);

            return 'unsigned';
        }

        $zoneDnskeys = $this->dnssecValidator->getCachedDnskeys($signerZone);

        if ($zoneDnskeys === null) {
            if ($this->dnssecValidator->isZoneInvalid($signerZone)) {
                foreach ($byRRset as $records) {
                    foreach ($records as $record) {
                        $this->dnssecValidator->setRecordValidation(
                            $record->name,
                            $record->type,
                            $record->data,
                            false,
                        );
                    }
                }

                return 'invalid';
            }

            return null;
        }

        $allSigned  = true;
        $anyInvalid = false;

        foreach ($byRRset as $rrsetKey => $records) {
            $type      = explode('|', $rrsetKey, 2)[1];
            $hasRrsig  = isset($rrsigs[$rrsetKey]);
            $validated = false;

            if ($hasRrsig) {
                $signerMatchesZone = false;

                foreach ($rrsigs[$rrsetKey] as $rrsig) {
                    if ($rrsig['signer'] === $signerZone) {
                        $signerMatchesZone = true;
                    }

                    $signingKey = $this->dnssecValidator->findSigningKey($rrsig, $zoneDnskeys);

                    if ($signingKey === null) {
                        continue;
                    }

                    $rrsetArrays = $this->toRawArrays($records);

                    if ($this->dnssecValidator->verifyRrsig($rrsig, $rrsetArrays, $signingKey)) {
                        $validated = true;

                        break;
                    }
                }

                if (!$validated) {
                    if ($signerMatchesZone) {
                        $this->dnssecValidator->markInvalid("RRSIG verification failed for {$type} records");
                        $anyInvalid = true;
                    } else {
                        // Records are signed by a different zone (e.g. CNAME target
                        // records included by the nameserver) — skip, don't fail.
                        $allSigned = false;
                    }
                }
            } else {
                $allSigned = false;
            }

            $recordStatus = $hasRrsig ? ($validated ?: null) : null;

            foreach ($records as $record) {
                $this->dnssecValidator->setRecordValidation(
                    $record->name,
                    $record->type,
                    $record->data,
                    $recordStatus,
                );
            }
        }

        if ($anyInvalid) {
            return 'invalid';
        }

        return $allSigned ? 'signed' : 'unsigned';
    }

    /**
     * @param list<RawRecord> $authority
     */
    private function validateEmptyResponse(array $authority, string $zone, string $nameserverAddr): ?string
    {
        if ($this->dnssecValidator === null) {
            return null;
        }

        $nsecRecords  = array_values(array_filter($authority, static fn (RawRecord $r) => in_array($r->type, ['NSEC', 'NSEC3'], true)));
        $soaRecords   = array_values(array_filter($authority, static fn (RawRecord $r) => $r->type === 'SOA'));
        $rrsigRecords = array_values(array_filter($authority, static fn (RawRecord $r) => $r->type === 'RRSIG'));

        if ($nsecRecords === [] && $soaRecords === []) {
            if ($this->dnssecValidator->getCachedDnskeys($zone) !== null) {
                $this->dnssecValidator->markInvalid('empty response is missing denial-of-existence records');

                return 'invalid';
            }

            return null;
        }

        if ($rrsigRecords === []) {
            if ($this->dnssecValidator->getCachedDnskeys($zone) !== null) {
                $this->dnssecValidator->markInvalid('empty response records are not signed');

                return 'invalid';
            }

            $this->dnssecValidator->markUnsigned($zone);

            return 'unsigned';
        }

        $signerZone = null;

        foreach ($rrsigRecords as $rrsigRecord) {
            $parsed = $this->dnssecValidator->parseRrsig($rrsigRecord->data);

            if ($parsed !== null) {
                $signerZone = $parsed['signer'];

                break;
            }
        }

        if ($signerZone === null) {
            if ($this->dnssecValidator->getCachedDnskeys($zone) !== null) {
                $this->dnssecValidator->markInvalid('failed to parse empty response RRSIGs');

                return 'invalid';
            }

            $this->dnssecValidator->markUnsigned($zone);

            return 'unsigned';
        }

        $zoneDnskeys = $this->dnssecValidator->getCachedDnskeys($signerZone);

        if ($zoneDnskeys === null) {
            if ($this->dnssecValidator->isZoneInvalid($signerZone)) {
                return 'invalid';
            }

            $zoneDnskeys = $this->fetchAndCacheDnskeys($signerZone, $nameserverAddr);

            if ($zoneDnskeys === null) {
                return null;
            }
        }

        // Validate RRSIG on NSEC/NSEC3 records
        if ($nsecRecords !== []) {
            foreach (['NSEC', 'NSEC3'] as $nsecType) {
                $typeRecords = array_values(array_filter($nsecRecords, static fn (RawRecord $r) => $r->type === $nsecType));

                if ($typeRecords === []) {
                    continue;
                }

                $recordsByOwner = [];

                foreach ($typeRecords as $r) {
                    $recordsByOwner[$r->name][] = $r;
                }

                $validatedCount = 0;
                $failedCount    = 0;

                foreach ($recordsByOwner as $ownerName => $ownerRecords) {
                    foreach ($rrsigRecords as $rrsigRecord) {
                        if ($rrsigRecord->name !== $ownerName) {
                            continue;
                        }

                        $rrsig = $this->dnssecValidator->parseRrsig($rrsigRecord->data);

                        if ($rrsig === null || $rrsig['type_covered'] !== $nsecType) {
                            continue;
                        }

                        $signingKey = $this->dnssecValidator->findSigningKey($rrsig, $zoneDnskeys);

                        if ($signingKey === null) {
                            continue;
                        }

                        $rrsetArrays = $this->toRawArrays($ownerRecords);

                        if ($this->dnssecValidator->verifyRrsig($rrsig, $rrsetArrays, $signingKey)) {
                            $validatedCount++;

                            break;
                        }

                        $failedCount++;

                        break;
                    }
                }

                if ($validatedCount > 0 && $failedCount === 0) {
                    return 'signed';
                }

                if ($failedCount > 0) {
                    $this->dnssecValidator->markInvalid("{$nsecType} RRSIG verification failed for empty response");

                    return 'invalid';
                }
            }
        }

        // Validate RRSIG on SOA record
        if ($soaRecords !== []) {
            $soaRrset = $this->toRawArrays($soaRecords);

            foreach ($rrsigRecords as $rrsigRecord) {
                $rrsig = $this->dnssecValidator->parseRrsig($rrsigRecord->data);

                if ($rrsig === null || $rrsig['type_covered'] !== 'SOA') {
                    continue;
                }

                $signingKey = $this->dnssecValidator->findSigningKey($rrsig, $zoneDnskeys);

                if ($signingKey === null) {
                    continue;
                }

                if ($this->dnssecValidator->verifyRrsig($rrsig, $soaRrset, $signingKey)) {
                    return 'signed';
                }

                $this->dnssecValidator->markInvalid('SOA RRSIG verification failed for empty response');

                return 'invalid';
            }
        }

        if ($this->dnssecValidator->getCachedDnskeys($zone) !== null) {
            $this->dnssecValidator->markInvalid('no valid RRSIG found for empty response');

            return 'invalid';
        }

        return null;
    }

    /**
     * @param list<RawRecord> $authority
     */
    private function validateNsecProofOfUnsigned(array $authority, string $currentZone, string $delegatedZone, string $nameserverAddr): ?string
    {
        if ($this->dnssecValidator === null) {
            return null;
        }

        $nsecRecords  = array_values(array_filter($authority, static fn (RawRecord $r) => in_array($r->type, ['NSEC', 'NSEC3'], true)));
        $rrsigRecords = array_values(array_filter($authority, static fn (RawRecord $r) => $r->type === 'RRSIG'));
        $zoneDnskeys  = $this->dnssecValidator->getCachedDnskeys($currentZone);

        if ($zoneDnskeys === null) {
            return 'unsigned';
        }

        if ($nsecRecords === [] || $rrsigRecords === []) {
            $this->dnssecValidator->markInvalid("missing authenticated proof that {$delegatedZone} is unsigned");

            return 'invalid';
        }

        $signerZone = $this->findSignerZone($rrsigRecords, ['NSEC', 'NSEC3']);

        if ($signerZone === null) {
            $this->dnssecValidator->markInvalid("failed to parse authenticated proof that {$delegatedZone} is unsigned");

            return 'invalid';
        }

        $zoneDnskeys = $this->dnssecValidator->getCachedDnskeys($signerZone);

        if ($zoneDnskeys === null) {
            if ($this->dnssecValidator->isZoneInvalid($signerZone)) {
                return 'invalid';
            }

            $zoneDnskeys = $this->fetchAndCacheDnskeys($signerZone, $nameserverAddr);

            if ($zoneDnskeys === null) {
                return null;
            }
        }

        foreach (['NSEC', 'NSEC3'] as $nsecType) {
            $typeRecords = array_values(array_filter($nsecRecords, static fn (RawRecord $r) => $r->type === $nsecType));

            if ($typeRecords === []) {
                continue;
            }

            $recordsByOwner = [];

            foreach ($typeRecords as $r) {
                $recordsByOwner[$r->name][] = $r;
            }

            foreach ($recordsByOwner as $ownerName => $ownerRecords) {
                foreach ($rrsigRecords as $rrsigRecord) {
                    if ($rrsigRecord->name !== $ownerName) {
                        continue;
                    }

                    $rrsig = $this->dnssecValidator->parseRrsig($rrsigRecord->data);

                    if ($rrsig === null || $rrsig['type_covered'] !== $nsecType || $rrsig['signer'] !== $signerZone) {
                        continue;
                    }

                    $signingKey = $this->dnssecValidator->findSigningKey($rrsig, $zoneDnskeys);

                    if ($signingKey === null) {
                        continue;
                    }

                    $rrsetArrays = $this->toRawArrays($ownerRecords);

                    if ($this->dnssecValidator->verifyRrsig($rrsig, $rrsetArrays, $signingKey)
                        && $this->provesUnsignedDelegation($ownerRecords, $delegatedZone, $currentZone)) {
                        return 'signed';
                    }
                }
            }
        }

        $this->dnssecValidator->markInvalid("NSEC proof of unsigned delegation failed for {$delegatedZone}");

        return 'invalid';
    }

    /**
     * @param list<RawRecord> $rrsigRecords
     * @param list<string>    $typesCovered
     */
    private function findSignerZone(array $rrsigRecords, array $typesCovered): ?string
    {
        if ($this->dnssecValidator === null) {
            return null;
        }

        foreach ($rrsigRecords as $rrsigRecord) {
            $parsed = $this->dnssecValidator->parseRrsig($rrsigRecord->data);

            if ($parsed !== null && in_array($parsed['type_covered'], $typesCovered, true)) {
                return $parsed['signer'];
            }
        }

        return null;
    }

    /**
     * @return list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}>|null
     */
    private function fetchAndCacheDnskeys(string $zone, string $nameserverAddr): ?array
    {
        if ($this->dnssecValidator === null) {
            return null;
        }

        try {
            $dnskeyResult = $this->query($zone, 'DNSKEY', $nameserverAddr, true);
        } catch (QueryException) {
            return null;
        }

        if ($dnskeyResult->answer === []) {
            return null;
        }

        $dnskeys = $this->parseDnskeysFromResult($dnskeyResult, $zone);

        if (empty($dnskeys)) {
            return null;
        }

        $dnskeyRrsig = null;

        foreach ($dnskeyResult->answer as $record) {
            if ($record->type === 'RRSIG') {
                $parsed = $this->dnssecValidator->parseRrsig($record->data);

                if ($parsed !== null && $parsed['type_covered'] === 'DNSKEY') {
                    $dnskeyRrsig = $parsed;

                    break;
                }
            }
        }

        if ($dnskeyRrsig === null) {
            $this->dnssecValidator->markUnsigned($zone);

            return null;
        }

        $signingKey = $this->dnssecValidator->findSigningKey($dnskeyRrsig, $dnskeys);

        if ($signingKey === null) {
            return null;
        }

        $dnskeyRrset = $this->toRawArrays(array_values(array_filter(
            $dnskeyResult->answer,
            static fn (RawRecord $r) => $r->type === 'DNSKEY',
        )));

        if (!$this->dnssecValidator->verifyRrsig($dnskeyRrsig, $dnskeyRrset, $signingKey)) {
            $this->dnssecValidator->markZoneInvalid($zone, "DNSKEY self-signature verification failed for {$zone}");

            return null;
        }

        $this->dnssecValidator->cacheDnskeys($zone, $dnskeys);

        return $dnskeys;
    }

    /**
     * @return list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}>
     */
    private function parseDnskeysFromResult(QueryResult $result, string $zone): array
    {
        if ($this->dnssecValidator === null) {
            return [];
        }

        $dnskeys = [];

        foreach ($result->answer as $record) {
            if ($record->type === 'DNSKEY') {
                $parsed = $this->dnssecValidator->parseDnskey($record->data, $zone);

                if ($parsed !== null) {
                    $dnskeys[] = $parsed;
                }
            }
        }

        return $dnskeys;
    }

    /**
     * Convert RawRecord DTOs to the array format expected by DnssecValidator.
     *
     * @param list<RawRecord> $records
     *
     * @return list<array{name: string, class: string, type: string, ttl: int, data: string}>
     */
    private function toRawArrays(array $records): array
    {
        return array_map(static fn (RawRecord $r) => [
            'name'  => $r->name,
            'class' => $r->class,
            'type'  => $r->type,
            'ttl'   => $r->ttl,
            'data'  => $r->data,
        ], $records);
    }

    /**
     * @param list<RawRecord> $records
     */
    private function provesUnsignedDelegation(array $records, string $delegatedZone, string $currentZone): bool
    {
        $record = $records[0] ?? null;

        if ($record === null) {
            return false;
        }

        return match ($record->type) {
            'NSEC'  => $this->nsecProvesUnsignedDelegation($record, $delegatedZone),
            'NSEC3' => $this->nsec3ProvesUnsignedDelegation($record, $delegatedZone, $currentZone),
            default => false,
        };
    }

    private function nsecProvesUnsignedDelegation(RawRecord $record, string $delegatedZone): bool
    {
        if (strtolower(rtrim($record->name, '.')) !== strtolower($delegatedZone)) {
            return false;
        }

        $parts = preg_split('/\s+/', trim($record->data));

        if ($parts === false || count($parts) < 2) {
            return false;
        }

        $types = array_map('strtoupper', array_slice($parts, 1));

        return in_array('NS', $types, true) && !in_array('DS', $types, true);
    }

    private function nsec3ProvesUnsignedDelegation(RawRecord $record, string $delegatedZone, string $currentZone): bool
    {
        if (!self::nameBelongsToZone($record->name, $currentZone)) {
            return false;
        }

        $parts = preg_split('/\s+/', trim($record->data));

        if ($parts === false || count($parts) < 6) {
            return false;
        }

        [$hashAlgorithm, $flags, $iterations, $salt, $nextOwner] = array_slice($parts, 0, 5);

        $types = array_map('strtoupper', array_slice($parts, 5));

        if ($hashAlgorithm !== '1' || !ctype_digit($flags) || !ctype_digit($iterations)) {
            return false;
        }

        $ownerHash     = strtoupper(explode('.', strtolower(rtrim($record->name, '.')), 2)[0]);
        $delegatedHash = $this->hashNsec3Owner($delegatedZone, (int)$iterations, $salt);
        $optOutEnabled = (((int)$flags) & 0x01) === 0x01;
        $nextOwnerHash = strtoupper($nextOwner);

        if (hash_equals($ownerHash, $delegatedHash)) {
            return in_array('NS', $types, true) && !in_array('DS', $types, true);
        }

        if (!$optOutEnabled) {
            return false;
        }

        return $this->nsec3RecordCoversHash($ownerHash, $nextOwnerHash, $delegatedHash);
    }

    private function nsec3RecordCoversHash(string $ownerHash, string $nextOwnerHash, string $targetHash): bool
    {
        if ($ownerHash === $nextOwnerHash) {
            return true;
        }

        $compareToOwner = strcmp($targetHash, $ownerHash);
        $compareToNext  = strcmp($targetHash, $nextOwnerHash);
        $compareRange   = strcmp($ownerHash, $nextOwnerHash);

        if ($compareRange < 0) {
            return $compareToOwner > 0 && $compareToNext < 0;
        }

        return $compareToOwner > 0 || $compareToNext < 0;
    }

    private function hashNsec3Owner(string $name, int $iterations, string $salt): string
    {
        $wire = (new WireFormatConverter)->nameToWire(strtolower(rtrim($name, '.')));
        $salt = $salt === '-' ? '' : hex2bin($salt);

        if ($salt === false) {
            return '';
        }

        $hash = sha1($wire . $salt, true);

        for ($i = 0; $i < $iterations; $i++) {
            $hash = sha1($hash . $salt, true);
        }

        return self::base32HexEncode($hash);
    }

    private static function base32HexEncode(string $data): string
    {
        $alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        $result   = '';
        $buffer   = 0;
        $bits     = 0;

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($data[$i]);
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $result .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }

        if ($bits > 0) {
            $result .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }

        return $result;
    }

    private static function nameBelongsToZone(string $name, string $zone): bool
    {
        $normalizedName = strtolower(rtrim($name, '.'));
        $normalizedZone = strtolower(rtrim($zone, '.'));

        if ($normalizedZone === '') {
            return true;
        }

        return $normalizedName === $normalizedZone || str_ends_with($normalizedName, '.' . $normalizedZone);
    }
}
