<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\ResolverConfig;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Events\EventType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Executors\DigQueryExecutor;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;
use ChiefTools\DNS\Resolver\Tests\Support\DeadlineFixtureExecutor;

describe('total resolution timeout', function () {
    it('shares the budget across every part of resolution and discards partial results', function (string $scenario) {
        $calls    = 0;
        $executor = new DeadlineFixtureExecutor(function (string $domain, string $type) use ($scenario, &$calls): QueryResult {
            $calls++;

            if ($calls === 1) {
                if ($scenario === 'fallback') {
                    throw new QueryException('timeout');
                }
                if ($scenario === 'alias') {
                    return new QueryResult(0, answer: [new RawRecord($domain . '.', 'IN', 'CNAME', 60, 'alias.deadline.test.')]);
                }
                if (in_array($scenario, ['delegation', 'nameserver'], true)) {
                    return new QueryResult(0,
                        authority: [new RawRecord('deadline.test.', 'IN', 'NS', 60, 'ns.deadline.test.')],
                        additional: $scenario === 'delegation' ? [new RawRecord('ns.deadline.test.', 'IN', 'A', 60, '192.0.2.83')] : [],
                    );
                }
                if ($scenario === 'dnssec') {
                    return new QueryResult(0);
                }
            }

            return new QueryResult(0, answer: [new RawRecord($domain . '.', 'IN', $type, 60, $type === 'AAAA' ? '2001:db8::83' : '192.0.2.83')]);
        });
        $resolver = new Resolver($executor, new ResolverConfig(totalTimeout: 1), clock: fn (): int => $executor->now);

        expect(fn () => $resolver->resolve('client.deadline.test', ['A', 'AAAA'], $scenario === 'dnssec' ? DnssecMode::ON : DnssecMode::OFF))
            ->toThrow(ResolutionTimeoutException::class);

        expect($executor->remaining)->toBe([1.0, 0.4]);
        expect($executor->deadlines[0])->toBe($executor->deadlines[1]);
        expect($calls)->toBe(2);
    })->with(['record types', 'alias', 'delegation', 'nameserver', 'fallback', 'dnssec']);

    it('starts a fresh budget and performs new queries for each resolve call', function () {
        $executor = new DeadlineFixtureExecutor(fn (string $domain): QueryResult => new QueryResult(0,
            answer: [new RawRecord($domain . '.', 'IN', 'A', 3600, '192.0.2.83')],
        ));
        $resolver = new Resolver($executor, new ResolverConfig(totalTimeout: 1), clock: fn (): int => $executor->now);

        $first  = $resolver->resolve('client.deadline.test', 'A', DnssecMode::OFF);
        $second = $resolver->resolve('client.deadline.test', 'A', DnssecMode::OFF);

        expect($first->records[0]->data)->toBe('192.0.2.83');
        expect($second->records[0]->data)->toBe('192.0.2.83');
        expect($executor->remaining)->toBe([1.0, 1.0]);
        expect($executor->deadlines[0])->not->toBe($executor->deadlines[1]);
    });

    it('allows query failure fallback while time remains', function () {
        $calls    = 0;
        $executor = new DeadlineFixtureExecutor(function (string $domain) use (&$calls): QueryResult {
            if (++$calls === 1) {
                throw new QueryException('timeout');
            }

            return new QueryResult(0, answer: [new RawRecord($domain . '.', 'IN', 'A', 60, '192.0.2.83')]);
        }, duration: 100_000_000);
        $resolver = new Resolver($executor, new ResolverConfig(totalTimeout: 1), clock: fn (): int => $executor->now);

        $result = $resolver->resolve('client.deadline.test', 'A', DnssecMode::OFF);

        expect($result->records[0]->data)->toBe('192.0.2.83');
        expect($executor->remaining)->toBe([1.0, 0.9]);
    });

    it('stops before a query when an event callback consumes the remaining budget', function () {
        $executor = new DeadlineFixtureExecutor(fn (): QueryResult => new QueryResult(0));
        $resolver = new Resolver($executor, new ResolverConfig(totalTimeout: 1), clock: fn (): int => $executor->now);

        expect(fn () => $resolver->resolve('client.deadline.test', 'A', DnssecMode::OFF,
            onEvent: function (ResolverEvent $event) use ($executor): void {
                if ($event->type === EventType::LOOKUP) {
                    $executor->now = 1_000_000_000;
                }
            },
        ))->toThrow(ResolutionTimeoutException::class);

        expect($executor->deadlines)->toBeEmpty();
    });

    it('rejects executors without deadline support before querying', function (string $executor) {
        expect(fn () => new Resolver(new $executor, new ResolverConfig(totalTimeout: 1)))
            ->toThrow(InvalidArgumentException::class, 'deadline-aware');
    })->with([FixtureExecutor::class, DigQueryExecutor::class]);

    it('rejects zone transfers before querying when a total timeout is configured', function (string $type) {
        $executor = new DeadlineFixtureExecutor(fn (): QueryResult => new QueryResult(0));
        $resolver = new Resolver($executor, new ResolverConfig(totalTimeout: 1));

        expect(fn () => $resolver->resolve('transfer.deadline.test', $type))->toThrow(InvalidArgumentException::class, 'Zone transfers');
        expect($executor->deadlines)->toBeEmpty();
    })->with(['AXFR', 'IXFR']);
});
