<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver;

use Closure;
use InvalidArgumentException;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;

final readonly class ResolutionDeadline
{
    private Closure $clock;
    private int $expiresAt;

    /** @param (\Closure(): int)|null $clock Monotonic time in nanoseconds. */
    public function __construct(float $timeout, ?Closure $clock = null)
    {
        if (!is_finite($timeout) || $timeout <= 0) {
            throw new InvalidArgumentException('The total timeout must be positive and finite.');
        }

        $this->clock = $clock ?? static fn (): int => hrtime(true);
        $now         = ($this->clock)();
        $duration    = $timeout * 1_000_000_000;

        $this->expiresAt = $duration >= PHP_INT_MAX - $now ? PHP_INT_MAX : $now + (int)$duration;
    }

    public function remaining(): float
    {
        $remaining = ($this->expiresAt - ($this->clock)()) / 1_000_000_000;

        if ($remaining <= 0) {
            throw new ResolutionTimeoutException('DNS resolution exceeded its total timeout.');
        }

        return $remaining;
    }

    public function throwIfExpired(): void
    {
        $this->remaining();
    }

    public function limit(float $timeout): self
    {
        return new self(min($timeout, $this->remaining()), $this->clock);
    }
}
