<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver;

use Closure;
use ChiefTools\DNS\Resolver\Results\Record;
use ChiefTools\DNS\Resolver\Data\RootServers;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;
use ChiefTools\DNS\Resolver\Results\DnssecResult;
use ChiefTools\DNS\Resolver\Results\LookupResult;
use ChiefTools\DNS\Resolver\Dnssec\DnssecValidator;
use ChiefTools\DNS\Resolver\Enums\RecordValidation;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;
use ChiefTools\DNS\Resolver\Executors\NetDns2QueryExecutor;

readonly class Resolver
{
    private DnsQueryExecutor $executor;
    private ResolverConfig   $config;

    public function __construct(
        ?DnsQueryExecutor $executor = null,
        ?ResolverConfig $config = null,
    ) {
        $this->executor = $executor ?? new NetDns2QueryExecutor;
        $this->config   = $config ?? new ResolverConfig;
    }

    /**
     * Resolve DNS records for a domain.
     *
     * @param RecordType|string|list<RecordType|string> $types   Record type(s) to query
     * @param (Closure(ResolverEvent): void)|null       $onEvent Optional callback for real-time resolution events
     */
    public function resolve(
        string $domain,
        RecordType|string|array $types = 'A',
        DnssecMode $dnssec = DnssecMode::ON,
        ?Closure $onEvent = null,
    ): LookupResult {
        $types = is_array($types) ? $types : [$types];

        // Normalize types to uppercase strings
        $types = array_map(
            static fn (RecordType|string $type) => $type instanceof RecordType ? $type->value : strtoupper($type),
            $types,
        );

        // Initialize DNSSEC validator if enabled
        $dnssecValidator = $dnssec !== DnssecMode::OFF ? new DnssecValidator : null;

        $engine = new ResolutionSession(
            executor: $this->executor,
            config: $this->config,
            dnssecValidator: $dnssecValidator,
            onEvent: $onEvent,
        );

        $results = $engine->resolve(
            domain: $domain,
            types: $types,
            nameservers: RootServers::random(ipv6: $this->config->ipv6),
        );

        // Build info message for non-result responses
        $info = null;

        if ($results === 'NXDOMAIN') {
            $info = 'The domain does not exist (NXDOMAIN).';
        } elseif (!is_array($results)) {
            $info = 'No records found for the requested ' . (count($types) === 1 ? 'type' : 'types') . '.';
        }

        // Build record DTOs
        $records = [];

        if (is_array($results)) {
            foreach ($results as $rawRecord) {
                $recordType = RecordType::tryFrom($rawRecord->type);

                if ($recordType === null) {
                    continue;
                }

                $validation = RecordValidation::UNKNOWN;

                if ($dnssecValidator !== null) {
                    $validatedStatus = $dnssecValidator->getRecordValidation($rawRecord->name, $rawRecord->type, $rawRecord->data);

                    $validation = match ($validatedStatus) {
                        true  => RecordValidation::SIGNED,
                        false => RecordValidation::FAILED,
                        null  => RecordValidation::UNKNOWN,
                    };
                }

                $records[] = new Record(
                    name: $rawRecord->name,
                    type: $recordType,
                    ttl: $rawRecord->ttl,
                    data: self::formatRecordData($rawRecord->type, $rawRecord->data),
                    rawData: $rawRecord->data,
                    validation: $validation,
                );
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

        return new LookupResult(
            records: $records,
            timeMs: $engine->getTotalTimeMs(),
            info: $info,
            dnssec: $dnssecResult,
        );
    }

    /**
     * Format record data for human readability.
     */
    private static function formatRecordData(string $type, string $data): string
    {
        return match ($type) {
            'TXT'            => '"' . str_replace('" "', '', $data) . '"',
            'AAAA'           => self::shortenIPv6($data),
            'TLSA', 'SMIMEA' => self::normalizeHexRecord($data, 3),
            'SSHFP'          => self::normalizeHexRecord($data, 2),
            'DS', 'CDS'      => self::normalizeHexRecord($data, 3),
            default          => $data,
        };
    }

    private static function shortenIPv6(string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        return inet_ntop($packed) ?: $ip;
    }

    /**
     * Normalize a record with hex data by removing spaces from the hex portion.
     */
    private static function normalizeHexRecord(string $data, int $prefixParts): string
    {
        $parts = preg_split('/\s+/', $data, $prefixParts + 1);

        if ($parts === false || count($parts) <= $prefixParts) {
            return $data;
        }

        $prefix  = implode(' ', array_slice($parts, 0, $prefixParts));
        $hexData = preg_replace('/\s+/', '', $parts[$prefixParts]);

        return $prefix . ' ' . $hexData;
    }
}
