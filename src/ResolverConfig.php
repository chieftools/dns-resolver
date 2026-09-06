<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver;

use InvalidArgumentException;

readonly class ResolverConfig
{
    public function __construct(
        public bool $ipv6 = true,
        public int $timeout = 2,
        public int $maxDepth = 10,
        public ?float $totalTimeout = null,
    ) {
        if ($totalTimeout !== null && (!is_finite($totalTimeout) || $totalTimeout <= 0)) {
            throw new InvalidArgumentException('The total timeout must be positive and finite.');
        }
    }
}
