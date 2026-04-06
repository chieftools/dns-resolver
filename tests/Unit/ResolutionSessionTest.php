<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\ResolverConfig;
use ChiefTools\DNS\Resolver\Events\EventType;
use ChiefTools\DNS\Resolver\ResolutionSession;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

function createSession(FixtureExecutor $executor, ?ResolverConfig $config = null, ?Closure $onEvent = null): ResolutionSession
{
    return new ResolutionSession(
        executor: $executor,
        config: $config ?? new ResolverConfig,
        onEvent: $onEvent,
    );
}

function ns(string $host, ?string $addr = null, bool $glue = false): array
{
    return ['host' => $host, 'addr' => $addr, 'glue' => $glue];
}

/**
 * Create an executor that throws QueryException for specific nameserver addresses.
 */
function failingExecutor(FixtureExecutor $inner, string ...$failAddrs): DnsQueryExecutor
{
    return new class($inner, $failAddrs) implements DnsQueryExecutor
    {
        public function __construct(
            private readonly FixtureExecutor $inner,
            /** @var list<string> */
            private readonly array $failAddrs,
        ) {}

        public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
        {
            if (in_array($nameserverAddr, $this->failAddrs, true)) {
                throw new QueryException("simulated failure for {$nameserverAddr}");
            }

            return $this->inner->query($domain, $type, $nameserverAddr, $dnssec);
        }
    };
}

describe('depth limit', function () {
    it('throws RuntimeException when max depth is exceeded', function () {
        $executor = new FixtureExecutor;
        $session  = createSession($executor, new ResolverConfig(maxDepth: 0));

        // Lookups check is $lookups > maxDepth, so lookups=1 with maxDepth=0 triggers it
        expect(fn () => $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')], lookups: 1))->toThrow(
            RuntimeException::class,
            'Too many recursive lookups!',
        );
    });

    it('allows resolution within depth limit', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor, new ResolverConfig(maxDepth: 1));

        $result = $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
    });
});

describe('empty inputs', function () {
    it('returns null for empty nameservers', function () {
        $executor = new FixtureExecutor;
        $session  = createSession($executor);

        $result = $session->resolve('example.com', ['A'], []);

        expect($result)->toBeNull();
    });

    it('returns null for empty types', function () {
        $executor = new FixtureExecutor;
        $session  = createSession($executor);

        $result = $session->resolve('example.com', [], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeNull();
    });
});

describe('direct answer', function () {
    it('resolves a simple A record', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->data)->toBe('93.184.216.34');
        expect($session->getTotalTimeMs())->toBe(10);
    });

    it('strips trailing dot from domain', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com.', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
    });

    it('filters out RRSIG records from answers', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [
                new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34'),
                new RawRecord('example.com.', 'IN', 'RRSIG', 300, 'A 13 2 300 20260406 20260404 34505 example.com. fakedata'),
            ],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->type)->toBe('A');
    });

    it('deduplicates identical records', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [
                new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34'),
                new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34'),
            ],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
    });
});

describe('multiple types', function () {
    it('queries additional types at the same nameserver', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));
        $executor->addFixture('example.com', 'AAAA', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'AAAA', 300, '2606:2800:220:1:248:1893:25c8:1946')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A', 'AAAA'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(2);

        $types = array_map(fn (RawRecord $r) => $r->type, $result);
        expect($types)->toContain('A');
        expect($types)->toContain('AAAA');
    });

    it('continues when additional type query throws exception', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));
        // No fixture for AAAA — will throw QueryException

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A', 'AAAA'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->type)->toBe('A');
    });

    it('handles additional type returning empty response', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));
        $executor->addFixture('example.com', 'MX', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A', 'MX'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->type)->toBe('A');
    });
});

describe('delegation', function () {
    it('follows NS delegation to child zone', function () {
        $executor = new FixtureExecutor;

        // Root delegates to child
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.example.com.')],
            additional: [new RawRecord('ns1.example.com.', 'IN', 'A', 86400, '5.6.7.8')],
            queryTimeMs: 5,
        ));

        // Child has the answer
        $executor->addFixture('example.com', 'A', '5.6.7.8', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->data)->toBe('93.184.216.34');
        expect($session->getTotalTimeMs())->toBe(15);
    });

    it('returns glue records that match the query', function () {
        $executor = new FixtureExecutor;

        // Delegation with glue records that answer the query directly
        $executor->addFixture('ns1.example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.example.com.')],
            additional: [
                new RawRecord('ns1.example.com.', 'IN', 'A', 86400, '5.6.7.8'),
            ],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('ns1.example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->data)->toBe('5.6.7.8');
    });

    it('ignores unrelated additional records when building the next nameserver list', function () {
        $executor = new FixtureExecutor;

        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.example.com.')],
            additional: [new RawRecord('stray.example.com.', 'IN', 'A', 86400, '7.7.7.7')],
            queryTimeMs: 5,
        ));
        $executor->addFixture('ns1.example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('ns1.example.com.', 'IN', 'A', 300, '5.6.7.8')],
            queryTimeMs: 5,
        ));
        $executor->addFixture('example.com', 'A', '5.6.7.8', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $session = createSession($executor, new ResolverConfig(ipv6: false));
        $result  = $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->data)->toBe('93.184.216.34');
    });
});

describe('query failure and fallback', function () {
    it('falls back to next nameserver on query failure', function () {
        $fixtures = new FixtureExecutor;
        $fixtures->addFixture('example.com', 'A', '5.6.7.8', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $executor = failingExecutor($fixtures, '1.2.3.4');
        $session  = new ResolutionSession(executor: $executor, config: new ResolverConfig);

        $result = $session->resolve(
            'example.com',
            ['A'],
            [ns('ns1.fail.com', '1.2.3.4'), ns('ns2.ok.com', '5.6.7.8')],
        );

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->data)->toBe('93.184.216.34');
    });

    it('returns null when all nameservers fail', function () {
        $fixtures = new FixtureExecutor;
        $executor = failingExecutor($fixtures, '1.2.3.4');
        $session  = new ResolutionSession(executor: $executor, config: new ResolverConfig);

        $result = $session->resolve(
            'example.com',
            ['A'],
            [ns('ns1.fail.com', '1.2.3.4')],
        );

        expect($result)->toBeNull();
    });

    it('emits failure and fallback events', function () {
        $fixtures = new FixtureExecutor;
        $fixtures->addFixture('example.com', 'A', '5.6.7.8', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $executor = failingExecutor($fixtures, '1.2.3.4');

        $events  = [];
        $session = new ResolutionSession(
            executor: $executor,
            config: new ResolverConfig,
            onEvent: function (ResolverEvent $event) use (&$events) {
                $events[] = $event;
            },
        );

        $session->resolve(
            'example.com',
            ['A'],
            [ns('ns1.fail.com', '1.2.3.4'), ns('ns2.ok.com', '5.6.7.8')],
        );

        $failureEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::QUERY_FAILURE));
        expect($failureEvents)->not->toBeEmpty();
        expect($failureEvents[0]->address)->toBe('1.2.3.4');

        $fallbackEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::NAMESERVER_FALLBACK));
        expect($fallbackEvents)->not->toBeEmpty();
        expect($fallbackEvents[0]->nameserver)->toBe('ns2.ok.com');
    });
});

describe('empty response', function () {
    it('returns null for authoritative empty response with no additional results', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('norecords.example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'SOA', 86400, 'ns1.example.com. admin.example.com. 2024 3600 900 604800 86400')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('norecords.example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeNull();
    });

    it('returns results when primary type is empty but additional type has records', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'SOA', 86400, 'ns1.example.com. admin.example.com. 2024 3600 900 604800 86400')],
            queryTimeMs: 5,
        ));
        $executor->addFixture('example.com', 'AAAA', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'AAAA', 300, '2001:db8::1')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A', 'AAAA'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->type)->toBe('AAAA');
    });
});

describe('NXDOMAIN handling', function () {
    it('returns NXDOMAIN when the nameserver responds with NXDOMAIN', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('missing.example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'SOA', 86400, 'ns1.example.com. admin.example.com. 2024 3600 900 604800 86400')],
            queryTimeMs: 5,
            responseCode: 'NXDOMAIN',
        ));

        $session = createSession($executor);
        $result  = $session->resolve('missing.example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBe('NXDOMAIN');
        expect($session->getTotalTimeMs())->toBe(5);
    });
});

describe('CNAME following', function () {
    it('follows CNAME and resolves the target', function () {
        $executor = new FixtureExecutor;

        // Initial query returns a CNAME
        $executor->addFixture('www.example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('www.example.com.', 'IN', 'CNAME', 300, 'example.com.')],
            queryTimeMs: 5,
        ));

        // CNAME target resolution — root delegates
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('www.example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();

        $cnameRecords = array_values(array_filter($result, fn (RawRecord $r) => $r->type === 'CNAME'));
        $aRecords     = array_values(array_filter($result, fn (RawRecord $r) => $r->type === 'A'));

        expect($cnameRecords)->toHaveCount(1);
        expect($aRecords)->toHaveCount(1);
        expect($aRecords[0]->data)->toBe('93.184.216.34');
    });

    it('returns CNAME records as-is when querying for CNAME type', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('www.example.com', 'CNAME', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('www.example.com.', 'IN', 'CNAME', 300, 'example.com.')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('www.example.com', ['CNAME'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(1);
        expect($result[0]->type)->toBe('CNAME');
        expect($result[0]->data)->toBe('example.com.');
    });

    it('stops following when a response contains a cyclic CNAME chain', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('www.example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [
                new RawRecord('www.example.com.', 'IN', 'CNAME', 300, 'alias.example.com.'),
                new RawRecord('alias.example.com.', 'IN', 'CNAME', 300, 'www.example.com.'),
            ],
            queryTimeMs: 5,
        ));

        $session = createSession($executor);
        $result  = $session->resolve('www.example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result)->toHaveCount(2);

        $cnameRecords = array_values(array_filter($result, fn (RawRecord $r) => $r->type === 'CNAME'));
        $aRecords     = array_values(array_filter($result, fn (RawRecord $r) => $r->type === 'A'));

        expect($cnameRecords)->toHaveCount(2);
        expect($aRecords)->toBeEmpty();
    });
});

describe('ipv6 config', function () {
    it('only uses A records for NS resolution when ipv6 is disabled', function () {
        $executor = new FixtureExecutor;

        // Delegation without glue
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.example.com.')],
            queryTimeMs: 5,
        ));

        // NS resolution — A query for ns1.example.com (simplified: answer directly from root)
        $executor->addFixture('ns1.example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('ns1.example.com.', 'IN', 'A', 300, '5.6.7.8')],
            queryTimeMs: 5,
        ));

        // Final answer
        $executor->addFixture('example.com', 'A', '5.6.7.8', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor, new ResolverConfig(ipv6: false));
        $result  = $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result[0]->data)->toBe('93.184.216.34');

        // Verify no AAAA queries were made
        $queries     = $executor->getQueries();
        $aaaaQueries = array_filter($queries, fn (array $q) => $q['type'] === 'AAAA');
        expect($aaaaQueries)->toBeEmpty();
    });
});

describe('events', function () {
    it('emits LOOKUP event with correct details', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $events  = [];
        $session = createSession($executor, onEvent: function (ResolverEvent $event) use (&$events) {
            $events[] = $event;
        });

        $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        $lookupEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::LOOKUP));

        expect($lookupEvents)->not->toBeEmpty();
        expect($lookupEvents[0]->domain)->toBe('example.com');
        expect($lookupEvents[0]->nameserver)->toBe('ns1.example.com');
        expect($lookupEvents[0]->address)->toBe('1.2.3.4');
        expect($lookupEvents[0]->glue)->toBeFalse();
    });

    it('marks glue nameservers in LOOKUP events', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $events  = [];
        $session = createSession($executor, onEvent: function (ResolverEvent $event) use (&$events) {
            $events[] = $event;
        });

        $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4', glue: true)]);

        $lookupEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::LOOKUP));

        expect($lookupEvents)->not->toBeEmpty();
        expect($lookupEvents[0]->glue)->toBeTrue();
    });

    it('emits DELEGATION event during NS delegation', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.example.com.')],
            additional: [new RawRecord('ns1.example.com.', 'IN', 'A', 86400, '5.6.7.8')],
            queryTimeMs: 5,
        ));
        $executor->addFixture('example.com', 'A', '5.6.7.8', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 10,
        ));

        $events  = [];
        $session = createSession($executor, onEvent: function (ResolverEvent $event) use (&$events) {
            $events[] = $event;
        });

        $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        $delegationEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::DELEGATION));

        expect($delegationEvents)->not->toBeEmpty();
        expect($delegationEvents[0]->domain)->toBe('example.com');
    });

    it('emits QUERY event with timing and type information', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 42,
        ));

        $events  = [];
        $session = createSession($executor, onEvent: function (ResolverEvent $event) use (&$events) {
            $events[] = $event;
        });

        $session->resolve('example.com', ['A'], [ns('ns1.example.com', '1.2.3.4')]);

        $queryEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::QUERY));

        expect($queryEvents)->not->toBeEmpty();
        expect($queryEvents[0]->recordType)->toBe('A');
        expect($queryEvents[0]->address)->toBe('1.2.3.4');
        expect($queryEvents[0]->timeMs)->toBe(42);
    });
});

describe('nameserver resolution', function () {
    it('returns null when nameserver address cannot be resolved', function () {
        $executor = new FixtureExecutor;

        // Delegation without glue — NS needs address resolution
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.unresolvable.test.')],
            additional: [], // No glue records — address resolution will be attempted
            queryTimeMs: 5,
        ));

        // No fixtures for ns1.unresolvable.test — resolution fails

        $session = createSession($executor);
        $result  = $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        expect($result)->toBeNull();
    });

    it('falls back to next nameserver when first cannot be resolved', function () {
        $executor = new FixtureExecutor;

        // Delegation without glue to two nameservers
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [
                new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.unresolvable.test.'),
                new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns2.example.com.'),
            ],
            additional: [], // No glue records
            queryTimeMs: 5,
        ));

        // ns2.example.com can be resolved (fixture matched by prefix)
        $executor->addFixture('ns2.example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('ns2.example.com.', 'IN', 'A', 300, '9.10.11.12')],
            queryTimeMs: 5,
        ));

        // Answer from the resolved nameserver
        $executor->addFixture('example.com', 'A', '9.10.11.12', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 5,
        ));

        $session = createSession($executor, new ResolverConfig(ipv6: false));
        $result  = $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        expect($result)->toBeArray();
        expect($result[0]->data)->toBe('93.184.216.34');
    });

    it('emits RESOLVE_FAILURE event when NS resolution fails', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            authority: [new RawRecord('example.com.', 'IN', 'NS', 86400, 'ns1.unresolvable.test.')],
            queryTimeMs: 5,
        ));

        $events  = [];
        $session = createSession($executor, onEvent: function (ResolverEvent $event) use (&$events) {
            $events[] = $event;
        });

        $session->resolve('example.com', ['A'], [ns('root.server', '1.2.3.4')]);

        $resolveFailureEvents = array_values(array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::RESOLVE_FAILURE));
        expect($resolveFailureEvents)->not->toBeEmpty();
        expect($resolveFailureEvents[0]->nameserver)->toBe('ns1.unresolvable.test');
    });
});

describe('accessor methods', function () {
    it('returns null for dnssec validator when not set', function () {
        $executor = new FixtureExecutor;
        $session  = createSession($executor);

        expect($session->getDnssecValidator())->toBeNull();
    });
});

describe('total time tracking', function () {
    it('accumulates query time across multiple queries', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
            queryTimeMs: 15,
        ));
        $executor->addFixture('example.com', 'AAAA', '1.2.3.4', new QueryResult(
            answer: [new RawRecord('example.com.', 'IN', 'AAAA', 300, '2001:db8::1')],
            queryTimeMs: 20,
        ));

        $session = createSession($executor);
        $session->resolve('example.com', ['A', 'AAAA'], [ns('ns1.example.com', '1.2.3.4')]);

        expect($session->getTotalTimeMs())->toBe(35);
    });

    it('starts at zero', function () {
        $executor = new FixtureExecutor;
        $session  = createSession($executor);

        expect($session->getTotalTimeMs())->toBe(0);
    });
});
