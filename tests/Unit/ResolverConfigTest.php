<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\ResolverConfig;

describe('ResolverConfig', function () {
    it('has sensible defaults', function () {
        $config = new ResolverConfig;

        expect($config->ipv6)->toBeTrue();
        expect($config->timeout)->toBe(2);
        expect($config->maxDepth)->toBe(10);
    });

    it('accepts custom values', function () {
        $config = new ResolverConfig(ipv6: false, timeout: 5, maxDepth: 20);

        expect($config->ipv6)->toBeFalse();
        expect($config->timeout)->toBe(5);
        expect($config->maxDepth)->toBe(20);
    });
});
