<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Executors;

/**
 * @internal
 */
readonly class RawRecord
{
    public function __construct(
        public string $name,
        public string $class,
        public string $type,
        public int $ttl,
        public string $data,
    ) {}
}
