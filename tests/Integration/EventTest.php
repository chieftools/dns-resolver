<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;
use ChiefTools\DNS\Resolver\Events\EventType;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('event system', function () {
    it('emits events during resolution', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/simple-a-record.json'),
        );

        $events = [];

        $resolver->resolve(
            domain: 'example.com',
            types: 'A',
            dnssec: DnssecMode::OFF,
            onEvent: function (ResolverEvent $event) use (&$events) {
                $events[] = $event;
            },
        );

        expect($events)->not->toBeEmpty();

        // Should have at least a LOOKUP event
        $lookupEvents = array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::LOOKUP);
        expect($lookupEvents)->not->toBeEmpty();

        // Should have at least a QUERY event
        $queryEvents = array_filter($events, fn (ResolverEvent $e) => $e->type === EventType::QUERY);
        expect($queryEvents)->not->toBeEmpty();

        // All events should have a message
        foreach ($events as $event) {
            expect($event->message)->not->toBeEmpty();
            expect($event->depth)->toBeGreaterThanOrEqual(0);
        }
    });

    it('provides structured data in events', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/simple-a-record.json'),
        );

        $events = [];

        $resolver->resolve(
            domain: 'example.com',
            types: 'A',
            dnssec: DnssecMode::OFF,
            onEvent: function (ResolverEvent $event) use (&$events) {
                $events[] = $event;
            },
        );

        // Find first LOOKUP event
        $lookupEvent = null;

        foreach ($events as $event) {
            if ($event->type === EventType::LOOKUP) {
                $lookupEvent = $event;
                break;
            }
        }

        expect($lookupEvent)->not->toBeNull();
        expect($lookupEvent->domain)->not->toBeNull();
        expect($lookupEvent->nameserver)->not->toBeNull();
        expect($lookupEvent->address)->not->toBeNull();
    });

    it('does not create events when no callback is provided', function () {
        $resolver = new Resolver(
            executor: FixtureExecutor::fromFile(__DIR__ . '/../Fixtures/simple-a-record.json'),
        );

        // This should work fine without any callback
        $result = $resolver->resolve('example.com', 'A', DnssecMode::OFF);

        expect($result->isEmpty())->toBeFalse();
    });
});
