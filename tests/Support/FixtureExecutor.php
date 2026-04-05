<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Tests\Support;

use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;

class FixtureExecutor implements DnsQueryExecutor
{
    /** @var array<string, QueryResult> */
    private array $fixtures = [];

    /** @var list<array{domain: string, type: string, nameserver: string, dnssec: bool}> */
    private array $queries = [];

    public static function fromFile(string $path): self
    {
        $data = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);

        $executor = new self;

        foreach ($data as $entry) {
            $key = $entry['key'];

            $executor->fixtures[$key] = new QueryResult(
                queryTimeMs: $entry['query_time_ms'] ?? 0,
                answer: self::convertSection($entry['answer'] ?? []),
                authority: self::convertSection($entry['authority'] ?? []),
                additional: self::convertSection($entry['additional'] ?? []),
            );
        }

        return $executor;
    }

    public function addFixture(string $domain, string $type, string $nameserverAddr, QueryResult $result): void
    {
        $key = self::buildKey($domain, $type, $nameserverAddr);

        $this->fixtures[$key] = $result;
    }

    public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        $this->queries[] = [
            'domain'     => $domain,
            'type'       => $type,
            'nameserver' => $nameserverAddr,
            'dnssec'     => $dnssec,
        ];

        $key = self::buildKey($domain, $type, $nameserverAddr);

        if (isset($this->fixtures[$key])) {
            return $this->fixtures[$key];
        }

        // Fall back to matching by domain|type with any nameserver (handles random root server selection)
        $prefix = "{$domain}|{$type}|";

        foreach ($this->fixtures as $fixtureKey => $result) {
            if (str_starts_with($fixtureKey, $prefix)) {
                return $result;
            }
        }

        throw new QueryException('no fixture for: ' . $key);
    }

    /**
     * @return list<array{domain: string, type: string, nameserver: string, dnssec: bool}>
     */
    public function getQueries(): array
    {
        return $this->queries;
    }

    private static function buildKey(string $domain, string $type, string $nameserverAddr): string
    {
        return "{$domain}|{$type}|{$nameserverAddr}";
    }

    /**
     * @param list<array{name: string, class: string, type: string, ttl: int, data: string}> $section
     *
     * @return list<RawRecord>
     */
    private static function convertSection(array $section): array
    {
        return array_map(
            static fn (array $record) => new RawRecord(
                name: $record['name'],
                class: $record['class'],
                type: $record['type'],
                ttl: $record['ttl'],
                data: $record['data'],
            ),
            $section,
        );
    }
}
