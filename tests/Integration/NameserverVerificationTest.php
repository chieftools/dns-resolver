<?php

declare(strict_types = 1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Results\Record;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\VerificationOptions;
use ChiefTools\DNS\Resolver\Results\AnswerSource;
use ChiefTools\DNS\Resolver\Results\LookupResult;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Enums\NameserverAnswerStatus;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;
use ChiefTools\DNS\Resolver\Results\AuthoritativeNameserver;
use ChiefTools\DNS\Resolver\Enums\NameserverVerificationStatus;

function verificationRecord(string $address, int $ttl = 60): Record
{
    return new Record('www.example.test.', RecordType::A, $ttl, $address, $address, sourceId: 1);
}

function verificationSource(array $nameservers, array $records): AnswerSource
{
    return new AnswerSource(
        id: 1,
        queryName: 'www.example.test',
        queryType: 'A',
        zone: 'example.test',
        nameservers: $nameservers,
        selectedNameserver: 'ns1.example.test',
        selectedAddress: '198.51.100.1',
        responseCode: 'NOERROR',
        records: $records,
    );
}

describe('authoritative nameserver verification', function () {
    it('captures the complete parent delegation and resolves a peer without glue', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('www.example.test', 'A', '192.0.2.1', new QueryResult(
            authority: [
                new RawRecord('example.test.', 'IN', 'NS', 60, 'ns1.example.test.'),
                new RawRecord('example.test.', 'IN', 'NS', 60, 'ns2.example.test.'),
            ],
            additional: [new RawRecord('ns1.example.test.', 'IN', 'A', 60, '198.51.100.1')],
            queryTimeMs: 1,
        ));
        $executor->addFixture('www.example.test', 'A', '198.51.100.1', new QueryResult(
            answer: [new RawRecord('www.example.test.', 'IN', 'A', 60, '203.0.113.10')],
            queryTimeMs: 1,
        ));
        $executor->addFixture('ns2.example.test', 'A', '192.0.2.1', new QueryResult(
            answer: [new RawRecord('ns2.example.test.', 'IN', 'A', 60, '198.51.100.2')],
            queryTimeMs: 1,
        ));
        $executor->addFixture('www.example.test', 'A', '198.51.100.2', new QueryResult(
            answer: [new RawRecord('www.example.test.', 'IN', 'A', 120, '203.0.113.10')],
            queryTimeMs: 1,
        ));

        $resolver = new Resolver($executor);
        $result   = $resolver->resolve('www.example.test', 'A', DnssecMode::OFF, captureAnswerSources: true);

        expect($result->answerSources)->toHaveCount(1);
        expect($result->answerSources[0]->zone)->toBe('example.test');
        expect(array_map(static fn (AuthoritativeNameserver $server): string => $server->host, $result->answerSources[0]->nameservers))
            ->toBe(['ns1.example.test', 'ns2.example.test']);
        expect($result->records[0]->sourceId)->toBe($result->answerSources[0]->id);

        $events       = [];
        $verification = $resolver->verifyNameservers($result, static function ($answer) use (&$events): void {
            $events[] = $answer;
        });

        expect($events)->toHaveCount(2);
        expect($events[0]->status)->toBe(NameserverAnswerStatus::BASELINE);
        expect($events[1]->status)->toBe(NameserverAnswerStatus::MATCH);
        expect($verification->sources[$result->answerSources[0]->id])->toBe(NameserverVerificationStatus::AGREE);
    });

    it('compares complete record sets without order or TTL and reports missing and extra values', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('www.example.test', 'A', '198.51.100.2', new QueryResult(
            answer: [
                new RawRecord('www.example.test.', 'IN', 'A', 120, '203.0.113.12'),
                new RawRecord('www.example.test.', 'IN', 'A', 120, '203.0.113.11'),
            ],
            queryTimeMs: 1,
        ));
        $executor->addFixture('www.example.test', 'A', '198.51.100.3', new QueryResult(
            answer: [
                new RawRecord('www.example.test.', 'IN', 'A', 120, '203.0.113.11'),
                new RawRecord('www.example.test.', 'IN', 'A', 120, '203.0.113.13'),
            ],
            queryTimeMs: 1,
        ));

        $source       = verificationSource([
            new AuthoritativeNameserver('ns1.example.test', ['198.51.100.1']),
            new AuthoritativeNameserver('ns2.example.test', ['198.51.100.2']),
            new AuthoritativeNameserver('ns3.example.test', ['198.51.100.3']),
        ], [verificationRecord('203.0.113.11'), verificationRecord('203.0.113.12')]);
        $lookup       = new LookupResult($source->records, 1, answerSources: [$source]);
        $verification = (new Resolver($executor))->verifyNameservers($lookup);

        expect($verification->answers[1]->status)->toBe(NameserverAnswerStatus::MATCH);
        expect($verification->answers[2]->status)->toBe(NameserverAnswerStatus::DIFFERENT);
        expect($verification->answers[2]->missing[0]->data)->toBe('203.0.113.12');
        expect($verification->answers[2]->extra[0]->data)->toBe('203.0.113.13');
        expect($verification->sources[1])->toBe(NameserverVerificationStatus::DIFFERENT);
    });

    it('tracks CNAME and target answers under their separate delegations', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('alias.example.test', 'A', '192.0.2.1', new QueryResult(
            authority: [new RawRecord('example.test.', 'IN', 'NS', 60, 'ns.example.test.')],
            additional: [new RawRecord('ns.example.test.', 'IN', 'A', 60, '198.51.100.1')],
            queryTimeMs: 1,
        ));
        $executor->addFixture('alias.example.test', 'A', '198.51.100.1', new QueryResult(
            answer: [new RawRecord('alias.example.test.', 'IN', 'CNAME', 60, 'target.other.test.')],
            queryTimeMs: 1,
        ));
        $executor->addFixture('target.other.test', 'A', '192.0.2.1', new QueryResult(
            authority: [new RawRecord('other.test.', 'IN', 'NS', 60, 'ns.other.test.')],
            additional: [new RawRecord('ns.other.test.', 'IN', 'A', 60, '198.51.100.2')],
            queryTimeMs: 1,
        ));
        $executor->addFixture('target.other.test', 'A', '198.51.100.2', new QueryResult(
            answer: [new RawRecord('target.other.test.', 'IN', 'A', 60, '203.0.113.24')],
            queryTimeMs: 1,
        ));

        $result = (new Resolver($executor))->resolve('alias.example.test', 'A', DnssecMode::OFF, captureAnswerSources: true);

        expect(array_map(static fn (AnswerSource $source): string => $source->zone, $result->answerSources))
            ->toBe(['example.test', 'other.test']);
        expect($result->records[0]->sourceId)->not->toBe($result->records[1]->sourceId);
    });

    it('does not contact filtered peer or delegation addresses', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('ns3.example.test', 'A', '192.0.2.1', new QueryResult(
            authority: [new RawRecord('example.test.', 'IN', 'NS', 60, 'ns4.example.test.')],
            additional: [new RawRecord('ns4.example.test.', 'IN', 'A', 60, '10.0.0.3')],
            queryTimeMs: 1,
        ));

        $source       = verificationSource([
            new AuthoritativeNameserver('ns1.example.test', ['198.51.100.1']),
            new AuthoritativeNameserver('ns2.example.test', ['10.0.0.2']),
            new AuthoritativeNameserver('ns3.example.test'),
        ], [verificationRecord('203.0.113.11')]);
        $lookup       = new LookupResult($source->records, 1, answerSources: [$source]);
        $verification = (new Resolver($executor))->verifyNameservers(
            $lookup,
            options: new VerificationOptions(20, static fn (string $address): bool => !str_starts_with($address, '10.')),
        );

        expect($verification->answers[1]->status)->toBe(NameserverAnswerStatus::UNAVAILABLE);
        expect($verification->answers[2]->status)->toBe(NameserverAnswerStatus::UNAVAILABLE);
        expect($verification->sources[1])->toBe(NameserverVerificationStatus::INCOMPLETE);
        expect(array_filter($executor->getQueries(), static fn (array $query): bool => str_starts_with($query['nameserver'], '10.')))->toBe([]);
    });

    it('marks exhausted deadlines as incomplete', function () {
        $source       = verificationSource([
            new AuthoritativeNameserver('ns1.example.test', ['198.51.100.1']),
            new AuthoritativeNameserver('ns2.example.test', ['10.0.0.2']),
            new AuthoritativeNameserver('ns3.example.test', ['198.51.100.3']),
        ], [verificationRecord('203.0.113.11')]);
        $lookup       = new LookupResult($source->records, 1, answerSources: [$source]);
        $now          = 0;
        $resolver     = new Resolver(new FixtureExecutor, clock: static function () use (&$now): int {
            return $now;
        });
        $verification = $resolver->verifyNameservers(
            $lookup,
            static function ($answer) use (&$now): void {
                if ($answer->status === NameserverAnswerStatus::BASELINE) {
                    $now = 21_000_000_000;
                }
            },
            new VerificationOptions(20, static fn (string $address): bool => !str_starts_with($address, '10.')),
        );

        expect($verification->answers[1]->status)->toBe(NameserverAnswerStatus::UNAVAILABLE);
        expect($verification->answers[2]->status)->toBe(NameserverAnswerStatus::UNAVAILABLE);
        expect($verification->sources[1])->toBe(NameserverVerificationStatus::INCOMPLETE);
    });
});
