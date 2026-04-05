<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Events;

readonly class ResolverEvent
{
    public function __construct(
        public EventType $type,
        public string $message,
        public int $depth,

        // Structured data — available depending on event type
        public ?string $domain = null,
        public ?string $recordType = null,
        public ?string $nameserver = null,
        public ?string $address = null,
        public ?int $timeMs = null,
        public ?string $status = null,
        public ?string $reason = null,
        public bool $glue = false,
    ) {}
}
