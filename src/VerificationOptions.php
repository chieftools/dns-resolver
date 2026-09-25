<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver;

use Closure;
use InvalidArgumentException;

readonly class VerificationOptions
{
    /** @param (\Closure(string): bool)|null $allowAddress */
    public function __construct(
        public float $totalTimeout = 20.0,
        public ?Closure $allowAddress = null,
    ) {
        if (!is_finite($totalTimeout) || $totalTimeout <= 0) {
            throw new InvalidArgumentException('The verification timeout must be positive and finite.');
        }
    }
}
