<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Results;

use ChiefTools\DNS\Resolver\Enums\RecordType;

readonly class LookupResult
{
    /**
     * @param list<Record> $records
     */
    public function __construct(
        public array $records,
        public int $timeMs,
        public ?string $info = null,
        public ?DnssecResult $dnssec = null,
    ) {}

    public function isEmpty(): bool
    {
        return $this->records === [];
    }

    public function isNxdomain(): bool
    {
        return $this->info !== null && str_contains($this->info, 'NXDOMAIN');
    }

    /**
     * Filter records by type.
     */
    public function ofType(RecordType|string $type): self
    {
        $typeValue = $type instanceof RecordType ? $type->value : $type;

        return new self(
            records: array_values(array_filter(
                $this->records,
                static fn (Record $r) => $r->type->value === $typeValue,
            )),
            timeMs: $this->timeMs,
            info: $this->info,
            dnssec: $this->dnssec,
        );
    }
}
