<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver;

readonly class ResolverConfig
{
    public function __construct(
        public bool $ipv6 = true,
        public int $timeout = 2,
        public int $maxDepth = 10,
    ) {}
}
