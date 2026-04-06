<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum DnssecMode
{
    /**
     * Disable DNSSEC validation for the lookup.
     *
     * The resolver will return records without building DNSSEC status or
     * per-record validation metadata.
     */
    case OFF;

    /**
     * Perform DNSSEC validation and report the outcome alongside the records.
     *
     * In this mode the resolver still returns lookup results even when DNSSEC
     * validation ends in an invalid state.
     */
    case ON;

    /**
     * Perform DNSSEC validation and treat invalid DNSSEC as a hard failure.
     *
     * When validation fails, records are cleared from the final result and the
     * failure is surfaced through the DNSSEC status and info message.
     */
    case STRICT;
}
