<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('CNAME following', function () {
    it('follows CNAME chain for www.github.com', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/cname-following.json'),
        );

        $result = $resolver->resolve('www.github.com', ['A', 'CNAME'], DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();

        // Should have CNAME record
        $cnameRecords = $result->ofType(RecordType::CNAME);
        expect($cnameRecords->records)->not->toBeEmpty();

        // Should also have A records from following the CNAME
        $aRecords = $result->ofType(RecordType::A);
        expect($aRecords->records)->not->toBeEmpty();
    });
});
