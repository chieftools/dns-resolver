<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('CNAME with invalid target', function () {
    it('does not follow a CNAME with a literal @ target', function () {
        $executor = new FixtureExecutor;

        // Root → delegation to example.com
        $executor->addFixture('www.example.com', 'A', '198.41.0.4', new QueryResult(
            queryTimeMs: 1,
            authority: [
                new RawRecord('example.com.', 'IN', 'NS', 172800, 'ns.example.com.'),
            ],
            additional: [
                new RawRecord('ns.example.com.', 'IN', 'A', 172800, '10.0.0.1'),
            ],
        ));

        // ns.example.com → CNAME with invalid literal '@' as target
        $executor->addFixture('www.example.com', 'A', '10.0.0.1', new QueryResult(
            queryTimeMs: 1,
            answer: [
                new RawRecord('www.example.com.', 'IN', 'CNAME', 300, '@'),
            ],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('www.example.com', 'A', DnssecMode::OFF);

        // Should have the CNAME record
        $cnames = $result->ofType(RecordType::CNAME);
        expect($cnames->records)->toHaveCount(1);
        expect($cnames->records[0]->data)->toBe('@');

        // Should NOT have any A records since the CNAME target is invalid
        $aRecords = $result->ofType(RecordType::A);
        expect($aRecords->records)->toBeEmpty();
    });

    it('does not follow a CNAME with an empty target', function () {
        $executor = new FixtureExecutor;

        $executor->addFixture('www.example.com', 'A', '198.41.0.4', new QueryResult(
            queryTimeMs: 1,
            authority: [
                new RawRecord('example.com.', 'IN', 'NS', 172800, 'ns.example.com.'),
            ],
            additional: [
                new RawRecord('ns.example.com.', 'IN', 'A', 172800, '10.0.0.1'),
            ],
        ));

        // CNAME with just a dot (which becomes empty after rtrim)
        $executor->addFixture('www.example.com', 'A', '10.0.0.1', new QueryResult(
            queryTimeMs: 1,
            answer: [
                new RawRecord('www.example.com.', 'IN', 'CNAME', 300, '.'),
            ],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('www.example.com', 'A', DnssecMode::OFF);

        $cnames = $result->ofType(RecordType::CNAME);
        expect($cnames->records)->toHaveCount(1);

        $aRecords = $result->ofType(RecordType::A);
        expect($aRecords->records)->toBeEmpty();
    });
});
