<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Executors;

use ChiefTools\DNS\Resolver\ResolutionDeadline;

interface DeadlineAwareDnsQueryExecutor extends DnsQueryExecutor
{
    public function queryWithDeadline(
        string $domain,
        string $type,
        string $nameserverAddr,
        bool $dnssec,
        ResolutionDeadline $deadline,
    ): QueryResult;
}
