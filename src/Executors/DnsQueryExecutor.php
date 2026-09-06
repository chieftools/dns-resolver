<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Executors;

interface DnsQueryExecutor
{
    /**
     * Execute a DNS query against a specific nameserver.
     *
     * @throws \ChiefTools\DNS\Resolver\Exceptions\QueryException
     */
    public function query(
        string $domain,
        string $type,
        string $nameserverAddr,
        bool $dnssec = false,
    ): QueryResult;
}
