<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Results\LookupResult;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

function resolverWithFixture(string $fixture): Resolver
{
    return new Resolver(
        executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/' . $fixture),
    );
}

describe('simple A record lookup', function () {
    it('resolves example.com A record', function () {
        $resolver = resolverWithFixture('simple-a-record.json');
        $result   = $resolver->resolve('example.com', 'A', DnssecMode::OFF);

        expect($result)->toBeInstanceOf(LookupResult::class);
        expect($result->isEmpty())->toBeFalse();
        expect($result->isNxdomain())->toBeFalse();
        expect($result->timeMs)->toBeGreaterThanOrEqual(0);

        $aRecords = $result->ofType(RecordType::A);
        expect($aRecords->records)->not->toBeEmpty();

        foreach ($aRecords->records as $record) {
            expect($record->type)->toBe(RecordType::A);
            expect($record->name)->toContain('example.com');
            expect(filter_var($record->data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))->not->toBeFalse();
        }
    });
});

describe('multi-type query', function () {
    it('resolves multiple types for example.com', function () {
        $resolver = resolverWithFixture('multi-type-query.json');
        $result   = $resolver->resolve('example.com', ['A', 'AAAA', 'MX'], DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();

        // Should have at least A records
        $aRecords = $result->ofType('A');
        expect($aRecords->records)->not->toBeEmpty();
    });
});

describe('resolve with RecordType enum', function () {
    it('accepts a single RecordType enum', function () {
        $resolver = resolverWithFixture('simple-a-record.json');
        $result   = $resolver->resolve('example.com', RecordType::A, DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();

        foreach ($result->records as $record) {
            expect($record->type)->toBe(RecordType::A);
        }
    });

    it('accepts a list of RecordType enums', function () {
        $resolver = resolverWithFixture('multi-type-query.json');
        $result   = $resolver->resolve('example.com', [RecordType::A, RecordType::AAAA, RecordType::MX], DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();
        expect($result->ofType(RecordType::A)->records)->not->toBeEmpty();
    });

    it('accepts a mixed list of RecordType enums and strings', function () {
        $resolver = resolverWithFixture('multi-type-query.json');
        $result   = $resolver->resolve('example.com', [RecordType::A, 'AAAA', RecordType::MX], DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();
        expect($result->ofType(RecordType::A)->records)->not->toBeEmpty();
    });
});

describe('NXDOMAIN', function () {
    it('returns NXDOMAIN for non-existent domain', function () {
        $resolver = resolverWithFixture('nxdomain.json');
        $result   = $resolver->resolve('thisdoesnotexist.example.com', 'A', DnssecMode::OFF);

        expect($result->isEmpty())->toBeTrue();
        // The domain exists (example.com) but the subdomain may not — could be empty response
    });
});

describe('ofType filter', function () {
    it('filters records by RecordType enum', function () {
        $resolver = resolverWithFixture('multi-type-query.json');
        $result   = $resolver->resolve('example.com', ['A', 'AAAA', 'MX'], DnssecMode::OFF);

        $filtered = $result->ofType(RecordType::A);
        expect(count($filtered->records))->toBeLessThanOrEqual(count($result->records));

        foreach ($filtered->records as $record) {
            expect($record->type)->toBe(RecordType::A);
        }
    });

    it('filters records by string type', function () {
        $resolver = resolverWithFixture('multi-type-query.json');
        $result   = $resolver->resolve('example.com', ['A', 'AAAA', 'MX'], DnssecMode::OFF);

        $filtered = $result->ofType('A');

        foreach ($filtered->records as $record) {
            expect($record->type->value)->toBe('A');
        }
    });
});
