<?php

declare(strict_types = 1);

use ChiefTools\DNS\Resolver\Tests\Support\LocalDnsServer;
use ChiefTools\DNS\Resolver\Executors\NetDns2QueryExecutor;

describe('netdns2 query executor', function () {
    it('uses EDNS so answers fit over UDP when the nameserver truncates and refuses TCP', function (bool $dnssec) {
        $server = new LocalDnsServer('edns-required');

        try {
            $result = new NetDns2QueryExecutor(timeout: 1, port: $server->port)->query('client.transport.test', 'A', '127.0.0.1', $dnssec);

            expect($result->answer)->toHaveCount(1);
            expect($result->answer[0]->data)->toBe('192.0.2.83');
            expect($server->output())->toContain('query:0:' . (int)$dnssec . ':1');
        } finally {
            $server->stop();
        }
    })->with([
        'without DNSSEC' => false,
        'with DNSSEC'    => true,
    ]);

    it('retries without EDNS when the nameserver answers EDNS queries with FORMERR', function (bool $dnssec) {
        $server = new LocalDnsServer('edns-formerr');

        try {
            $result = new NetDns2QueryExecutor(timeout: 1, port: $server->port)->query('client.transport.test', 'A', '127.0.0.1', $dnssec);
            $output = $server->output();

            expect($result->responseCode)->toBe('NOERROR');
            expect($result->answer)->toHaveCount(1);
            expect($result->answer[0]->data)->toBe('192.0.2.83');
            expect($output)->toContain('query:0:' . (int)$dnssec . ':1');
            expect($output)->toContain('query:0:0:0');
        } finally {
            $server->stop();
        }
    })->with([
        'without DNSSEC' => false,
        'with DNSSEC'    => true,
    ]);
});
