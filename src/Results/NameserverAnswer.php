<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Results;

use ChiefTools\DNS\Resolver\Enums\NameserverAnswerStatus;

readonly class NameserverAnswer
{
    /**
     * @param list<Record> $records
     * @param list<Record> $missing
     * @param list<Record> $extra
     */
    public function __construct(
        public int $sourceId,
        public string $nameserver,
        public ?string $address,
        public ?string $responseCode,
        public array $records,
        public NameserverAnswerStatus $status,
        public array $missing = [],
        public array $extra = [],
        public ?string $reason = null,
    ) {}
}
