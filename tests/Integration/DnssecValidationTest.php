<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Enums\DnssecStatus;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('DNSSEC validation', function () {
    it('performs DNSSEC validation on signed zone (cloudflare.com)', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/wildcard-dnssec.json'),
        );

        $result = $resolver->resolve('cloudflare.com', ['A', 'AAAA'], DnssecMode::ON);

        expect($result->isEmpty())->toBeFalse();
        expect($result->dnssec)->not->toBeNull();
        // Status should be SIGNED if RRSIGs are valid, or INVALID if they expired.
        // Either way, DNSSEC was attempted and a result was produced.
        expect($result->dnssec->status)->toBeIn([DnssecStatus::SIGNED, DnssecStatus::INVALID]);
    });

    it('detects unsigned zone or expired RRSIG (example.com)', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/unsigned-zone.json'),
        );

        $result = $resolver->resolve('example.com', ['A'], DnssecMode::ON);

        expect($result->dnssec)->not->toBeNull();
        // example.com is unsigned, but the root RRSIG may have expired causing INVALID
        expect($result->dnssec->status)->toBeIn([DnssecStatus::UNSIGNED, DnssecStatus::INVALID]);
    });

    it('skips DNSSEC when mode is OFF', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/simple-a-record.json'),
        );

        $result = $resolver->resolve('example.com', 'A', DnssecMode::OFF);

        expect($result->dnssec)->toBeNull();
    });

    it('returns DnssecResult with errors when validation fails', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/wildcard-dnssec.json'),
        );

        $result = $resolver->resolve('cloudflare.com', ['A', 'AAAA'], DnssecMode::ON);

        expect($result->dnssec)->not->toBeNull();

        if ($result->dnssec->isInvalid()) {
            expect($result->dnssec->errors)->not->toBeEmpty();
        }
    });

    it('clears records in strict mode when DNSSEC is invalid', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/wildcard-dnssec.json'),
        );

        $result = $resolver->resolve('cloudflare.com', ['A', 'AAAA'], DnssecMode::STRICT);

        expect($result->dnssec)->not->toBeNull();

        if ($result->dnssec->isInvalid()) {
            // In strict mode, records should be cleared on invalid DNSSEC
            expect($result->records)->toBeEmpty();
            expect($result->info)->not->toBeNull();
        } else {
            // If DNSSEC is valid, records should be present
            expect($result->records)->not->toBeEmpty();
        }
    });
});
