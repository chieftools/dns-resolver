<?php

declare(strict_types = 1);

use ChiefTools\DNS\Resolver\ResolutionDeadline;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;

describe('resolution deadline', function () {
    it('uses one monotonic expiry and fails exactly at the boundary', function () {
        $now      = 3_000_000_000;
        $deadline = new ResolutionDeadline(0.5, function () use (&$now): int { return $now; });

        $now += 125_000_000;
        expect($deadline->remaining())->toBe(0.375);

        $now += 375_000_000;
        expect(fn () => $deadline->remaining())->toThrow(ResolutionTimeoutException::class);
    });

    it('rejects invalid timeouts', function (float $timeout) {
        expect(fn () => new ResolutionDeadline($timeout))->toThrow(InvalidArgumentException::class);
    })->with(['zero' => 0.0, 'negative' => -1.0, 'infinite' => INF, 'not a number' => NAN]);

    it('caps query budgets by the remaining total time', function () {
        $now      = 0;
        $deadline = new ResolutionDeadline(1, function () use (&$now): int { return $now; });
        $now      = 750_000_000;

        expect($deadline->limit(2)->remaining())->toBe(0.25);
        expect($deadline->limit(0.1)->remaining())->toBe(0.1);
    });
});
