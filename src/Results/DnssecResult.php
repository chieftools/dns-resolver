<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Results;

use ChiefTools\DNS\Resolver\Enums\DnssecStatus;

readonly class DnssecResult
{
    /**
     * @param list<string> $errors
     */
    public function __construct(
        public DnssecStatus $status,
        public array $errors = [],
    ) {}

    public function isSigned(): bool
    {
        return $this->status === DnssecStatus::SIGNED;
    }

    public function isInvalid(): bool
    {
        return $this->status === DnssecStatus::INVALID;
    }
}
