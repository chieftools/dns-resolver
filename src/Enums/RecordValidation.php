<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum RecordValidation
{
    /**
     * The record's RRset was covered by a signature that the resolver
     * successfully verified.
     *
     * Callers can treat this record as authenticated within the scope of the
     * current lookup's DNSSEC evaluation.
     */
    case SIGNED;

    /**
     * The record's RRset was expected to validate, but signature verification
     * failed or required DNSSEC proof was broken.
     *
     * This indicates a bogus record outcome rather than a merely unsigned one.
     */
    case FAILED;

    /**
     * The resolver has no definitive per-record validation result.
     *
     * This usually means DNSSEC was disabled, no applicable signature was
     * present, or the record was outside the validated scope of the lookup.
     */
    case UNKNOWN;
}
