<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Executors;

use JsonException;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;

class DigQueryExecutor implements DnsQueryExecutor
{
    public function __construct(
        private readonly string $digPath = '/usr/bin/dig',
        private readonly string $jcPath = '/usr/local/bin/jc',
    ) {}

    public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        $dnssecFlag = $dnssec ? '+dnssec' : '';

        $result = shell_exec(
            sprintf(
                '%s +norecurse +time=2 +tries=1 %s -t %s -q %s %s | %s --dig',
                $this->digPath,
                $dnssecFlag,
                escapeshellarg($type),
                escapeshellarg($domain),
                escapeshellarg("@{$nameserverAddr}"),
                $this->jcPath,
            ),
        );

        if (!$result) {
            throw new QueryException('timeout');
        }

        try {
            /** @var list<array{query_time?: int, answer_num?: int, answer?: list<array{name: string, class: string, type: string, ttl: int, data: string}>, authority?: list<array{name: string, class: string, type: string, ttl: int, data: string}>, additional?: list<array{name: string, class: string, type: string, ttl: int, data: string}>}> $parsed */
            $parsed = json_decode($result, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new QueryException('parse error');
        }

        $data = $parsed[0] ?? throw new QueryException('parse error');

        return new QueryResult(
            queryTimeMs: $data['query_time'] ?? 0,
            answer: $this->convertSection($data['answer'] ?? []),
            authority: $this->convertSection($data['authority'] ?? []),
            additional: $this->convertSection($data['additional'] ?? []),
        );
    }

    /**
     * @param list<array{name: string, class: string, type: string, ttl: int, data: string}> $section
     *
     * @return list<RawRecord>
     */
    private function convertSection(array $section): array
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
