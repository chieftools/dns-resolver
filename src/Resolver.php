<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver;

use Closure;
use InvalidArgumentException;
use ChiefTools\DNS\Resolver\Results\Record;
use ChiefTools\DNS\Resolver\Data\RootServers;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Enums\LookupStatus;
use ChiefTools\DNS\Resolver\Results\AnswerSource;
use ChiefTools\DNS\Resolver\Results\DnssecResult;
use ChiefTools\DNS\Resolver\Results\LookupResult;
use ChiefTools\DNS\Resolver\Dnssec\DnssecValidator;
use ChiefTools\DNS\Resolver\Enums\RecordValidation;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;
use ChiefTools\DNS\Resolver\Executors\NetDns2QueryExecutor;
use ChiefTools\DNS\Resolver\Results\AuthoritativeNameserver;
use ChiefTools\DNS\Resolver\Results\NameserverVerificationResult;
use ChiefTools\DNS\Resolver\Executors\DeadlineAwareDnsQueryExecutor;

readonly class Resolver
{
    private DnsQueryExecutor $executor;
    private ResolverConfig   $config;

    /** @param (\Closure(): int)|null $clock Monotonic time in nanoseconds. */
    public function __construct(
        ?DnsQueryExecutor $executor = null,
        ?ResolverConfig $config = null,
        private ?Closure $clock = null,
    ) {
        $this->config   = $config ?? new ResolverConfig;
        $this->executor = $executor ?? new NetDns2QueryExecutor(
            timeout: $this->config->timeout,
        );

        if ($this->config->totalTimeout !== null && !$this->executor instanceof DeadlineAwareDnsQueryExecutor) {
            throw new InvalidArgumentException('A total timeout requires a deadline-aware DNS query executor.');
        }
    }

    /**
     * Resolve DNS records for a domain.
     *
     * @param \ChiefTools\DNS\Resolver\Enums\RecordType|string|list<\ChiefTools\DNS\Resolver\Enums\RecordType|string> $types   \ChiefTools\DNS\Resolver\Results\Record type(s) to query
     * @param (\Closure(\ChiefTools\DNS\Resolver\Events\ResolverEvent): void)|null                                    $onEvent Optional callback for real-time resolution events
     */
    public function resolve(
        string $domain,
        RecordType|string|array $types = 'A',
        DnssecMode $dnssec = DnssecMode::ON,
        ?Closure $onEvent = null,
        bool $captureAnswerSources = false,
    ): LookupResult {
        $deadline = $this->config->totalTimeout !== null
            ? new ResolutionDeadline($this->config->totalTimeout, $this->clock)
            : null;

        $types = is_array($types) ? $types : [$types];

        // Normalize types to uppercase strings
        $types = array_map(
            static fn (RecordType|string $type) => $type instanceof RecordType ? $type->value : strtoupper($type),
            $types,
        );

        if ($deadline !== null && array_intersect($types, ['AXFR', 'IXFR']) !== []) {
            throw new InvalidArgumentException('Zone transfers do not support a total timeout.');
        }

        // Initialize DNSSEC validator if enabled
        $dnssecValidator = $dnssec !== DnssecMode::OFF ? new DnssecValidator : null;

        $engine = new ResolutionSession(
            executor: $this->executor,
            config: $this->config,
            dnssecValidator: $dnssecValidator,
            onEvent: $onEvent,
            deadline: $deadline,
            captureAnswerSources: $captureAnswerSources,
        );

        $results = $engine->resolve(
            domain: $domain,
            types: $types,
            nameservers: RootServers::random(ipv6: $this->config->ipv6),
        );

        // Build info message for non-result responses
        $status = match (true) {
            $results === 'NXDOMAIN'     => LookupStatus::NXDOMAIN,
            $results === 'QUERY_FAILED' => LookupStatus::QUERY_FAILED,
            is_array($results)          => LookupStatus::SUCCESS,
            default                     => LookupStatus::NO_RECORDS,
        };

        $info = match ($status) {
            LookupStatus::NXDOMAIN     => 'The domain does not exist.',
            LookupStatus::QUERY_FAILED => 'The lookup could not be completed because no nameserver responded successfully.',
            LookupStatus::NO_RECORDS   => 'No records were found for the requested ' . (count($types) === 1 ? 'type' : 'types') . '.',
            LookupStatus::SUCCESS      => null,
        };

        // Build record DTOs
        $records          = [];
        $formattedByRawId = [];
        $sourceIds        = $captureAnswerSources ? $engine->getRecordSourceIds() : [];

        if (is_array($results)) {
            foreach ($results as $rawRecord) {
                $validation = RecordValidation::UNKNOWN;

                if ($dnssecValidator !== null) {
                    $validatedStatus = $dnssecValidator->getRecordValidation($rawRecord->name, $rawRecord->type, $rawRecord->data);

                    $validation = match ($validatedStatus) {
                        true  => RecordValidation::SIGNED,
                        false => RecordValidation::FAILED,
                        null  => RecordValidation::UNKNOWN,
                    };
                }

                $rawId  = spl_object_id($rawRecord);
                $record = RecordFormatter::fromRaw($rawRecord, $validation, $sourceIds[$rawId] ?? null);

                if ($record !== null) {
                    $records[]                = $record;
                    $formattedByRawId[$rawId] = $record;
                }
            }
        }

        // Build DNSSEC result
        $dnssecResult = null;

        if ($dnssecValidator !== null) {
            $dnssecResult = new DnssecResult(
                status: $dnssecValidator->getStatus(),
                errors: $dnssecValidator->getErrors(),
            );

            // In strict mode, clear records if validation is invalid
            if ($dnssec === DnssecMode::STRICT && $dnssecResult->isInvalid()) {
                $records = [];
                $info    = 'DNSSEC validation failed: ' . implode('; ', $dnssecResult->errors);
            }
        }

        $answerSources = null;
        if ($captureAnswerSources) {
            $answerSources = [];
            foreach ($engine->getAnswerSources() as $source) {
                $sourceRecords = [];
                foreach ($source['records'] as $rawRecord) {
                    $record = $formattedByRawId[spl_object_id($rawRecord)] ?? null;
                    if ($record !== null && in_array($record, $records, true)) {
                        $sourceRecords[] = $record;
                    }
                }

                if ($sourceRecords === []) {
                    continue;
                }

                $nameservers = [];
                foreach ($source['nameservers'] as $candidate) {
                    $key = strtolower(rtrim($candidate['host'], '.'));
                    if (!isset($nameservers[$key])) {
                        $nameservers[$key] = ['host' => $candidate['host'], 'addresses' => []];
                    }
                    if (!empty($candidate['glue']) && $candidate['addr'] !== null) {
                        $nameservers[$key]['addresses'][$candidate['addr']] = true;
                    }
                }

                $answerSources[] = new AnswerSource(
                    id: $source['id'],
                    queryName: $source['queryName'],
                    queryType: $source['queryType'],
                    zone: $source['zone'],
                    nameservers: array_values(array_map(
                        static fn (array $candidate): AuthoritativeNameserver => new AuthoritativeNameserver(
                            $candidate['host'],
                            array_keys($candidate['addresses']),
                        ),
                        $nameservers,
                    )),
                    selectedNameserver: $source['selectedNameserver'],
                    selectedAddress: $source['selectedAddress'],
                    responseCode: $source['responseCode'],
                    records: $sourceRecords,
                );
            }
        }

        $deadline?->throwIfExpired();

        return new LookupResult(
            records: $records,
            timeMs: $engine->getTotalTimeMs(),
            status: $status,
            dnssec: $dnssecResult,
            info: $info,
            answerSources: $answerSources,
        );
    }

    /** @param (\Closure(\ChiefTools\DNS\Resolver\Results\NameserverAnswer): void)|null $onAnswer */
    public function verifyNameservers(
        LookupResult $result,
        ?Closure $onAnswer = null,
        ?VerificationOptions $options = null,
    ): NameserverVerificationResult {
        return (new NameserverVerifier($this->executor, $this->config, $this->clock))
            ->verify($result, $onAnswer, $options ?? new VerificationOptions);
    }
}
