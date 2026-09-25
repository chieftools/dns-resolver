<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Results;

use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Enums\LookupStatus;

readonly class LookupResult
{
    /** @param list<Record> $records */
    public function __construct(
        public array $records,
        public int $timeMs,
        public ?string $info = null,
        public LookupStatus $status = LookupStatus::SUCCESS,
        public ?DnssecResult $dnssec = null,
        /** @var list<AnswerSource>|null */
        public ?array $answerSources = null,
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

    /** Filter records by type. */
    public function ofType(RecordType|string $type): self
    {
        $typeValue = $type instanceof RecordType ? $type->value : $type;

        $records = array_values(array_filter(
            $this->records,
            static fn (Record $record): bool => $record->type->value === $typeValue,
        ));

        $sources = $this->answerSources === null ? null : array_values(array_filter(array_map(
            static function (AnswerSource $source) use ($typeValue): ?AnswerSource {
                $sourceRecords = array_values(array_filter(
                    $source->records,
                    static fn (Record $record): bool => $record->type->value === $typeValue,
                ));

                return $sourceRecords === [] ? null : new AnswerSource(
                    id: $source->id,
                    queryName: $source->queryName,
                    queryType: $source->queryType,
                    zone: $source->zone,
                    nameservers: $source->nameservers,
                    selectedNameserver: $source->selectedNameserver,
                    selectedAddress: $source->selectedAddress,
                    responseCode: $source->responseCode,
                    records: $sourceRecords,
                );
            },
            $this->answerSources,
        )));

        return new self(
            records: $records,
            timeMs: $this->timeMs,
            status: $this->status,
            dnssec: $this->dnssec,
            info: $this->info,
            answerSources: $sources,
        );
    }
}
