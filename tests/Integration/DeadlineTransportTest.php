<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\ResolutionDeadline;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Tests\Support\LocalDnsServer;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;
use ChiefTools\DNS\Resolver\Executors\DeadlineAwareNetDns2Transport;

describe('deadline transport', function () {
    it('bounds unresponsive and incrementally responding nameservers', function (string $scenario) {
        $server    = new LocalDnsServer($scenario);
        $started   = hrtime(true);
        $transport = new DeadlineAwareNetDns2Transport(new ResolutionDeadline(0.1), '127.0.0.1', 2, port: $server->port);

        try {
            expect(fn () => $transport->query('client.transport.test', 'A'))->toThrow(ResolutionTimeoutException::class);
            expect((hrtime(true) - $started) / 1_000_000_000)->toBeLessThan(0.75);

            if ($scenario !== 'silent') {
                expect($server->waitForClose())->toContain('closed');
            }
        } finally {
            $server->stop();
        }
    })->with(['silent', 'tcp-stall', 'tcp-trickle']);

    it('keeps a shorter query timeout recoverable while the total budget remains', function () {
        $server    = new LocalDnsServer('silent');
        $deadline  = new ResolutionDeadline(1);
        $transport = new DeadlineAwareNetDns2Transport($deadline, '127.0.0.1', 0.05, port: $server->port);

        try {
            expect(fn () => $transport->query('client.transport.test', 'A'))->toThrow(QueryException::class, 'timeout');
            expect($deadline->remaining())->toBeGreaterThan(0.5);
        } finally {
            $server->stop();
        }
    });

    it('reads answers over UDP and TCP without requesting recursion or caching responses', function (string $scenario, bool $dnssec, string $type, string $address) {
        $server = new LocalDnsServer($scenario);

        try {
            for ($attempt = 0; $attempt < 2; $attempt++) {
                $transport = new DeadlineAwareNetDns2Transport(new ResolutionDeadline(1), '127.0.0.1', 1, $dnssec, $server->port);
                $response  = $transport->query('client.transport.test', $type);
                expect(rtrim((string)$response->answer[0]->name, '.'))->toBe('client.transport.test');
                expect(inet_pton((string)$response->answer[0]->address))->toBe(inet_pton($address));
            }

            expect(substr_count($server->output(), 'query:0:' . (int)$dnssec))->toBe($scenario === 'tcp-answer' ? 4 : 2);
        } finally {
            $server->stop();
        }
    })->with([
        'UDP'          => ['answer', false, 'A', '192.0.2.83'],
        'UDP DNSSEC'   => ['answer', true, 'A', '192.0.2.83'],
        'AAAA'         => ['answer', false, 'AAAA', '2001:db8::83'],
        'TCP fallback' => ['tcp-answer', false, 'A', '192.0.2.83'],
    ]);

    it('rejects responses that do not match the request', function (string $scenario) {
        $server    = new LocalDnsServer($scenario);
        $transport = new DeadlineAwareNetDns2Transport(new ResolutionDeadline(1), '127.0.0.1', 1, port: $server->port);

        try {
            expect(fn () => $transport->query('client.transport.test', 'A'))->toThrow(QueryException::class, 'invalid response');
        } finally {
            $server->stop();
        }
    })->with(['wrong-id', 'wrong-question', 'wrong-qr', 'wrong-opcode']);

    it('treats a prematurely closed TCP connection as a recoverable query failure', function () {
        $server    = new LocalDnsServer('tcp-close');
        $deadline  = new ResolutionDeadline(1);
        $transport = new DeadlineAwareNetDns2Transport($deadline, '127.0.0.1', 1, port: $server->port);

        try {
            expect(fn () => $transport->query('client.transport.test', 'A'))->toThrow(QueryException::class, 'connection error');
            expect($deadline->remaining())->toBeGreaterThan(0);
        } finally {
            $server->stop();
        }
    });

    it('preserves authoritative negative responses', function () {
        $server    = new LocalDnsServer('nxdomain');
        $transport = new DeadlineAwareNetDns2Transport(new ResolutionDeadline(1), '127.0.0.1', 1, port: $server->port);

        try {
            $response = $transport->query('client.transport.test', 'A');
            expect($response->header->rcode->name)->toBe('NXDOMAIN');
            expect($response->answer)->toBeEmpty();
        } finally {
            $server->stop();
        }
    });

    it('refuses nameserver hostnames rather than resolving them through the system resolver', function () {
        expect(fn () => new DeadlineAwareNetDns2Transport(new ResolutionDeadline(1), 'ns.transport.test', 1))
            ->toThrow(QueryException::class, 'IP address');
    });
});
