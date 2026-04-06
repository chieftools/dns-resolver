<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Executors;

/**
 * @internal
 */
readonly class QueryResult
{
    /**
     * @param list<RawRecord> $answer
     * @param list<RawRecord> $authority
     * @param list<RawRecord> $additional
     */
    public function __construct(
        public int $queryTimeMs,
        public array $answer = [],
        public array $authority = [],
        public array $additional = [],
        public string $responseCode = 'NOERROR',
    ) {}
}
