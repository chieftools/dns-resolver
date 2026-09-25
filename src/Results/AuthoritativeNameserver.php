<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Results;

readonly class AuthoritativeNameserver
{
    /** @param list<string> $addresses Addresses supplied as delegation glue. */
    public function __construct(
        public string $host,
        public array $addresses = [],
    ) {}
}
