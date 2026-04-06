<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Results;

use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Enums\LookupStatus;

readonly class LookupResult
{
    /**
     * @param list<Record> $records
     */
    public function __construct(
        public array $records,
        public int $timeMs,
        public ?string $info = null,
        public LookupStatus $status = LookupStatus::SUCCESS,
        public ?DnssecResult $dnssec = null,
    ) {}

    public function isEmpty(): bool
    {
        return $this->records === [];
    }

    public function isNxdomain(): bool
    {
        return $this->status === LookupStatus::NXDOMAIN;
    }

    public function isLookupFailed(): bool
    {
        return $this->status === LookupStatus::QUERY_FAILED;
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
            status: $this->status,
            dnssec: $this->dnssec,
            info: $this->info,
        );
    }
}
