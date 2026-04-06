<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum LookupStatus: string
{
    /**
     * The resolver returned one or more records for the requested lookup.
     *
     * This covers both fully successful answers and answers that still carry
     * DNSSEC warnings in non-strict mode.
     */
    case SUCCESS = 'success';

    /**
     * The lookup completed, but no records were returned for the requested
     * type or types.
     *
     * This usually means an empty/NODATA-style response rather than a missing
     * domain or transport failure.
     */
    case NO_RECORDS = 'no_records';

    /**
     * An authoritative server reported that the queried domain name does not
     * exist.
     *
     * Callers can treat this as a definitive non-existence signal for the
     * lookup target rather than a transient resolver failure.
     */
    case NXDOMAIN = 'nxdomain';

    /**
     * The resolver could not complete the lookup because every candidate
     * nameserver failed to answer successfully.
     *
     * This generally points to timeout, network, transport, or server
     * availability problems and may succeed on retry.
     */
    case QUERY_FAILED = 'query_failed';
}
