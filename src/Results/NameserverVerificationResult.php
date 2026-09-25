<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Results;

readonly class NameserverVerificationResult
{
    /**
     * @param list<NameserverAnswer>                                                  $answers
     * @param array<int, \ChiefTools\DNS\Resolver\Enums\NameserverVerificationStatus> $sources
     */
    public function __construct(
        public array $answers,
        public array $sources,
    ) {}
}
