<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('nameserver resolution', function () {
    it('resolves github.com with delegation', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/nameserver-resolution.json'),
        );

        $result = $resolver->resolve('github.com', ['A', 'NS'], DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();

        // Should have A records
        $aRecords = $result->ofType(RecordType::A);
        expect($aRecords->records)->not->toBeEmpty();
    });
});
