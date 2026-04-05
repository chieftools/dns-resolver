<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Executors;

use ChiefTools\DNS\Resolver\Exceptions\QueryException;

interface DnsQueryExecutor
{
    /**
     * Execute a DNS query against a specific nameserver.
     *
     * @throws QueryException
     */
    public function query(
        string $domain,
        string $type,
        string $nameserverAddr,
        bool $dnssec = false,
    ): QueryResult;
}
