<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Results;

use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Enums\RecordValidation;

readonly class Record
{
    public function __construct(
        public string $name,
        public RecordType $type,
        public int $ttl,
        public string $data,
        public string $rawData,
        public RecordValidation $validation = RecordValidation::UNKNOWN,
    ) {}
}
