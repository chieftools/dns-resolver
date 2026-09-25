<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Results;

readonly class AnswerSource
{
    /**
     * @param list<AuthoritativeNameserver> $nameservers
     * @param list<Record>                  $records
     */
    public function __construct(
        public int $id,
        public string $queryName,
        public string $queryType,
        public string $zone,
        public array $nameservers,
        public string $selectedNameserver,
        public string $selectedAddress,
        public string $responseCode,
        public array $records,
    ) {}
}
