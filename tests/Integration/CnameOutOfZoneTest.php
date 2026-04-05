<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('CNAME with out-of-zone records', function () {
    it('discards out-of-zone records from answer when following CNAME', function () {
        $executor = new FixtureExecutor;

        // Root → delegation to example.com
        $executor->addFixture('alias.example.com', 'A', '198.41.0.4', new QueryResult(
            queryTimeMs: 1,
            authority: [
                new RawRecord('example.com.', 'IN', 'NS', 172800, 'ns.example.com.'),
            ],
            additional: [
                new RawRecord('ns.example.com.', 'IN', 'A', 172800, '10.0.0.1'),
            ],
        ));

        // ns.example.com → CNAME with out-of-zone A record included
        // This simulates a nameserver that helpfully includes the CNAME target's A record.
        $executor->addFixture('alias.example.com', 'A', '10.0.0.1', new QueryResult(
            queryTimeMs: 1,
            answer: [
                new RawRecord('alias.example.com.', 'IN', 'CNAME', 300, 'target.other.com.'),
                new RawRecord('target.other.com.', 'IN', 'A', 300, '10.99.99.99'),
            ],
        ));

        // CNAME following resolves target.other.com from root
        // Root → delegation to other.com
        $executor->addFixture('target.other.com', 'A', '198.41.0.4', new QueryResult(
            queryTimeMs: 1,
            authority: [
                new RawRecord('other.com.', 'IN', 'NS', 172800, 'ns.other.com.'),
            ],
            additional: [
                new RawRecord('ns.other.com.', 'IN', 'A', 172800, '10.0.0.2'),
            ],
        ));

        // ns.other.com → the real A record (different IP from the out-of-zone one)
        $executor->addFixture('target.other.com', 'A', '10.0.0.2', new QueryResult(
            queryTimeMs: 1,
            answer: [
                new RawRecord('target.other.com.', 'IN', 'A', 300, '10.1.2.3'),
            ],
        ));

        $resolver = new Resolver(executor: $executor);
        $result   = $resolver->resolve('alias.example.com', 'A', DnssecMode::OFF);

        // Should have the CNAME
        $cnames = $result->ofType(RecordType::CNAME);
        expect($cnames->records)->toHaveCount(1);
        expect($cnames->records[0]->data)->toBe('target.other.com.');

        // Should have A record from the proper CNAME resolution, not the out-of-zone one
        $aRecords = $result->ofType(RecordType::A);
        expect($aRecords->records)->toHaveCount(1);
        expect($aRecords->records[0]->data)->toBe('10.1.2.3');
    });
});
