<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\ResolverConfig;
use ChiefTools\DNS\Resolver\Events\EventType;
use ChiefTools\DNS\Resolver\ResolutionSession;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Dnssec\DnssecValidator;
use ChiefTools\DNS\Resolver\Tests\Support\FixtureExecutor;

describe('chained CNAME DNSSEC validation', function () {
    it('validates each CNAME RRset independently when response contains chained CNAMEs', function () {
        // Custom validator that returns true when the RRset contains exactly one record.
        // With the fix (grouping by name|type), each CNAME is verified as its own RRset
        // of 1 record → returns true → validation passes.
        // Without the fix (grouping by type only), both CNAMEs would be in one RRset
        // of 2 records → returns false → "RRSIG verification failed for CNAME records".
        $validator = new class extends DnssecValidator
        {
            public function verifyRrsig(array $rrsig, array $rrset, array $dnskey): bool
            {
                return count($rrset) === 1;
            }
        };

        $validator->cacheDnskeys('example.com', [
            [
                'keytag'         => 12345,
                'algorithm'      => 13,
                'flags'          => 257,
                'protocol'       => 3,
                'public_key'     => 'fake',
                'public_key_b64' => 'ZmFrZQ==',
                'name'           => 'example.com.',
                'is_ksk'         => true,
            ],
        ]);

        $executor = new FixtureExecutor;

        // Nameserver returns chained CNAMEs with their respective RRSIGs
        $executor->addFixture('www.example.com', 'A', '10.0.0.1', new QueryResult(
            answer: [
                new RawRecord('www.example.com.', 'IN', 'CNAME', 300, 'alias.example.com.'),
                new RawRecord('www.example.com.', 'IN', 'RRSIG', 300, 'CNAME 13 3 300 20270101000000 20260101000000 12345 example.com. dGVzdA=='),
                new RawRecord('alias.example.com.', 'IN', 'CNAME', 300, 'target.example.com.'),
                new RawRecord('alias.example.com.', 'IN', 'RRSIG', 300, 'CNAME 13 3 300 20270101000000 20260101000000 12345 example.com. dGVzdA=='),
            ],
            queryTimeMs: 1,
        ));

        // Root → delegation to example.com for CNAME target resolution
        $executor->addFixture('target.example.com', 'A', '198.41.0.4', new QueryResult(
            authority: [
                new RawRecord('example.com.', 'IN', 'NS', 172800, 'ns.example.com.'),
            ],
            additional: [
                new RawRecord('ns.example.com.', 'IN', 'A', 172800, '10.0.0.2'),
            ],
            queryTimeMs: 1,
        ));

        // Answer for the final CNAME target
        $executor->addFixture('target.example.com', 'A', '10.0.0.2', new QueryResult(
            answer: [
                new RawRecord('target.example.com.', 'IN', 'A', 300, '93.184.216.34'),
            ],
            queryTimeMs: 1,
        ));

        $events = [];

        $session = new ResolutionSession(
            executor: $executor,
            config: new ResolverConfig,
            dnssecValidator: $validator,
            onEvent: function (ResolverEvent $event) use (&$events) {
                $events[] = $event;
            },
        );

        $result = $session->resolve(
            'www.example.com',
            ['A'],
            [['host' => 'ns.example.com', 'addr' => '10.0.0.1', 'glue' => true]],
            currentZone: 'example.com',
        );

        // Find the first QUERY event (the chained CNAME response validation)
        $cnameQueryEvent = current(array_filter(
            $events,
            fn (ResolverEvent $e) => $e->type === EventType::QUERY && $e->domain === 'www.example.com',
        ));

        // The chained CNAME response should validate as signed, not invalid
        expect($cnameQueryEvent)->not->toBeFalse();
        expect($cnameQueryEvent->status)->toBe('signed');

        // No RRSIG verification errors for CNAME records
        $cnameErrors = array_filter(
            $validator->getErrors(),
            fn ($e) => str_contains($e, 'RRSIG verification failed for CNAME'),
        );
        expect($cnameErrors)->toBeEmpty();

        // Resolution should still return the final A record
        expect($result)->toBeArray();
        expect($result)->not->toBeEmpty();

        $aRecords = array_filter($result, fn (RawRecord $r) => $r->type === 'A');
        expect($aRecords)->not->toBeEmpty();
    });
});
