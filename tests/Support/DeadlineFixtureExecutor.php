<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Tests\Support;

use Closure;
use LogicException;
use ChiefTools\DNS\Resolver\ResolutionDeadline;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Executors\DeadlineAwareDnsQueryExecutor;

class DeadlineFixtureExecutor implements DeadlineAwareDnsQueryExecutor
{
    public int $now = 0;

    /** @var list<\ChiefTools\DNS\Resolver\ResolutionDeadline> */
    public array $deadlines = [];

    /** @var list<float> */
    public array $remaining = [];

    /** @var list<string> */
    public array $types = [];

    /** @param \Closure(string, string, string, bool): \ChiefTools\DNS\Resolver\Executors\QueryResult $response */
    public function __construct(
        private Closure $response,
        private int $duration = 600_000_000,
    ) {}

    public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        throw new LogicException('The resolver must pass the deadline.');
    }

    public function queryWithDeadline(string $domain, string $type, string $nameserverAddr, bool $dnssec, ResolutionDeadline $deadline): QueryResult
    {
        $this->deadlines[]  = $deadline;
        $this->remaining[]  = $deadline->remaining();
        $this->types[]      = $type;
        $this->now         += $this->duration;

        return ($this->response)($domain, $type, $nameserverAddr, $dnssec);
    }
}
