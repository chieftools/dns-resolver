<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Tests\Support;

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;

class FixtureRecorder implements DnsQueryExecutor
{
    /** @var list<array{key: string, query_time_ms: int, response_code: string, answer: list<array<string, mixed>>, authority: list<array<string, mixed>>, additional: list<array<string, mixed>>}> */
    private array $recordings = [];

    public function __construct(
        private readonly DnsQueryExecutor $inner,
    ) {}

    public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        $result = $this->inner->query($domain, $type, $nameserverAddr, $dnssec);

        $this->recordings[] = [
            'key'           => "{$domain}|{$type}|{$nameserverAddr}",
            'query_time_ms' => $result->queryTimeMs,
            'response_code' => $result->responseCode,
            'answer'        => array_map(self::serializeRecord(...), $result->answer),
            'authority'     => array_map(self::serializeRecord(...), $result->authority),
            'additional'    => array_map(self::serializeRecord(...), $result->additional),
        ];

        return $result;
    }

    /**
     * Record a complete lookup and save all executor calls as a fixture.
     *
     * @param string|list<string> $types
     */
    public function record(string $domain, string|array $types, bool $dnssec = true): void
    {
        $resolver = new Resolver(
            executor: $this,
        );

        $resolver->resolve(
            domain: $domain,
            types: $types,
            dnssec: $dnssec ? DnssecMode::ON : DnssecMode::OFF,
        );
    }

    public function save(string $path): void
    {
        $dir = dirname($path);

        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents(
            $path,
            json_encode($this->recordings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
        );
    }

    /**
     * @return list<array{key: string, query_time_ms: int, response_code: string, answer: list<array<string, mixed>>, authority: list<array<string, mixed>>, additional: list<array<string, mixed>>}>
     */
    public function getRecordings(): array
    {
        return $this->recordings;
    }

    /**
     * @return array{name: string, class: string, type: string, ttl: int, data: string}
     */
    private static function serializeRecord(RawRecord $record): array
    {
        return [
            'name'  => $record->name,
            'class' => $record->class,
            'type'  => $record->type,
            'ttl'   => $record->ttl,
            'data'  => $record->data,
        ];
    }
}
