<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Enums\RecordValidation;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

function resolverWithDirectAnswer(string $domain, string $type, string $ns, QueryResult $result): Resolver
{
    $executor = new FixtureExecutor;
    $executor->addFixture($domain, $type, $ns, $result);

    return new Resolver(executor: $executor);
}

describe('record formatting', function () {
    it('formats TXT records by stripping inner quotes and wrapping', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'TXT', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'TXT', 300, 'v=spf1 include:_spf.google.com" "~all')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'TXT', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('"v=spf1 include:_spf.google.com~all"');
        expect($result->records[0]->rawData)->toBe('v=spf1 include:_spf.google.com" "~all');
    });

    it('shortens AAAA records', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'AAAA', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'AAAA', 300, '2001:0db8:0000:0000:0000:0000:0000:0001')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'AAAA', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('2001:db8::1');
    });

    it('returns invalid IPv6 unchanged', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'AAAA', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'AAAA', 300, 'not-an-ip')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'AAAA', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('not-an-ip');
    });

    it('normalizes DS record hex data', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'DS', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'DS', 300, '2371 13 2 c988ec42 3e3880eb 8dd8a46f')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'DS', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('2371 13 2 c988ec423e3880eb8dd8a46f');
    });

    it('normalizes CDS record hex data', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'CDS', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'CDS', 300, '2371 13 2 aabb ccdd')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'CDS', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('2371 13 2 aabbccdd');
    });

    it('normalizes SSHFP record hex data', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'SSHFP', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'SSHFP', 300, '1 1 aa bb cc dd ee ff')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'SSHFP', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('1 1 aabbccddeeff');
    });

    it('normalizes TLSA record hex data', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('_443._tcp.example.com', 'TLSA', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('_443._tcp.example.com.', 'IN', 'TLSA', 300, '3 1 1 aa bb cc')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('_443._tcp.example.com', 'TLSA', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('3 1 1 aabbcc');
    });

    it('normalizes SMIMEA record hex data', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('hash._smimecert.example.com', 'SMIMEA', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('hash._smimecert.example.com.', 'IN', 'SMIMEA', 300, '3 1 1 dd ee ff')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('hash._smimecert.example.com', 'SMIMEA', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('3 1 1 ddeeff');
    });

    it('passes through default record types unchanged', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'MX', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'MX', 300, '10 mail.example.com.')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'MX', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('10 mail.example.com.');
    });

    it('returns hex record unchanged when no hex portion exists', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'DS', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'DS', 300, '2371 13')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'DS', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->data)->toBe('2371 13');
    });
});

describe('unknown record types', function () {
    it('skips records with types not in the RecordType enum', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [
                new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34'),
                new RawRecord('example.com.', 'IN', 'UNKNOWNTYPE', 300, 'some data'),
            ],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'A', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->type)->toBe(RecordType::A);
    });
});

describe('empty and null results', function () {
    it('returns info about no records when resolution returns null', function () {
        $executor = new FixtureExecutor;
        // No fixtures at all — executor will throw QueryException for any query,
        // which makes ResolutionSession return null via handleQueryFailure
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
        ));
        // Empty response with no authority NS → handleEmptyResponse → null

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'A', DnssecMode::OFF);

        expect($result->isEmpty())->toBeTrue();
        expect($result->info)->toBe('No records found for the requested type.');
    });

    it('uses plural types in info message for multiple types', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
        ));
        $executor->addFixture('example.com', 'AAAA', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', ['A', 'AAAA'], DnssecMode::OFF);

        expect($result->isEmpty())->toBeTrue();
        expect($result->info)->toBe('No records found for the requested types.');
    });
});

describe('record validation', function () {
    it('sets validation to UNKNOWN when DNSSEC is off', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'A', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->validation)->toBe(RecordValidation::UNKNOWN);
    });
});

describe('type normalization', function () {
    it('normalizes lowercase string types to uppercase', function () {
        $executor = new FixtureExecutor;
        $executor->addFixture('example.com', 'A', '1.2.3.4', new QueryResult(
            queryTimeMs: 5,
            answer: [new RawRecord('example.com.', 'IN', 'A', 300, '93.184.216.34')],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('example.com', 'a', DnssecMode::OFF);

        expect($result->records)->toHaveCount(1);
        expect($result->records[0]->type)->toBe(RecordType::A);
    });
});
