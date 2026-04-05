<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\ResolverConfig;
use ChiefTools\DNS\Resolver\ResolutionSession;
use ChiefTools\DNS\Resolver\Dnssec\DnssecValidator;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;

/**
 * Executor that throws QueryException for queries to specific nameserver addresses.
 */
$failingExecutorClass = new class implements DnsQueryExecutor {
    /** @var array<string, QueryResult> */
    private array $fixtures = [];

    /** @var list<string> */
    private array $failAddresses = [];

    public function failAddress(string $addr): void
    {
        $this->failAddresses[] = $addr;
    }

    public function addFixture(string $domain, string $type, string $addr, QueryResult $result): void
    {
        $this->fixtures["{$domain}|{$type}|{$addr}"] = $result;
    }

    public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        if (in_array($nameserverAddr, $this->failAddresses, true)) {
            throw new QueryException("timeout (simulated)");
        }

        $key = "{$domain}|{$type}|{$nameserverAddr}";

        return $this->fixtures[$key] ?? throw new QueryException("no fixture for: {$key}");
    }
};

describe('DNSSEC resilience', function () use ($failingExecutorClass) {
    it('does not mark zone invalid when DNSKEY fetch times out and fallback succeeds', function () use ($failingExecutorClass) {
        $executor = clone $failingExecutorClass;

        // ns1 (10.0.0.1): ALL queries timeout
        $executor->failAddress('10.0.0.1');

        // ns2 (10.0.0.2): DNSKEY returns a valid-looking response
        $executor->addFixture('example.com', 'DNSKEY', '10.0.0.2', new QueryResult(
            queryTimeMs: 1,
            answer: [
                new RawRecord('example.com.', 'IN', 'DNSKEY', 7200, '257 3 13 dummykey'),
            ],
        ));

        // ns2: main query returns an answer
        $executor->addFixture('test.example.com', 'A', '10.0.0.2', new QueryResult(
            queryTimeMs: 1,
            answer: [
                new RawRecord('test.example.com.', 'IN', 'A', 300, '93.184.216.34'),
            ],
        ));

        $validator = new DnssecValidator;
        $session   = new ResolutionSession(
            executor: $executor,
            config: new ResolverConfig,
            dnssecValidator: $validator,
        );

        $result = $session->resolve(
            'test.example.com',
            ['A'],
            [
                ['host' => 'ns1.example.com', 'addr' => '10.0.0.1', 'glue' => true],
                ['host' => 'ns2.example.com', 'addr' => '10.0.0.2', 'glue' => true],
            ],
            parentDs: [['keytag' => 12345, 'algorithm' => 13, 'digest_type' => 2, 'digest' => 'ABCD']],
            currentZone: 'example.com',
        );

        expect($result)->toBeArray();
        expect($result)->not->toBeEmpty();
        expect($result[0]->data)->toBe('93.184.216.34');

        // The critical assertion: no "failed to fetch DNSKEY" errors from the timeout.
        // The zone may be invalid for other reasons (DS mismatch), but NOT because
        // the first nameserver timed out.
        $fetchErrors = array_filter(
            $validator->getErrors(),
            fn ($e) => str_contains($e, 'failed to fetch DNSKEY'),
        );

        expect($fetchErrors)->toBeEmpty('DNSKEY timeout should not produce fetch errors when fallback succeeds');
    });
});
