<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum DnssecStatus: string
{
    /**
     * DNSSEC validation succeeded for the parts of the lookup result that were
     * expected to be signed.
     *
     * This means the resolver was able to build and verify the relevant trust
     * chain without detecting any signature or delegation failures.
     */
    case SIGNED        = 'signed';

    /**
     * The lookup completed without usable DNSSEC signatures for one or more
     * relevant zones, but no validation failure was detected.
     *
     * This commonly occurs for unsigned zones or unsigned delegations where
     * the resolver treats the result as insecure rather than broken.
     */
    case UNSIGNED      = 'unsigned';

    /**
     * DNSSEC validation failed.
     *
     * This covers cases such as bad signatures, missing required proofs, or
     * broken trust-chain material that should cause the result to be treated
     * as bogus.
     */
    case INVALID       = 'invalid';

    /**
     * The resolver did not reach a definitive DNSSEC conclusion.
     *
     * This is typically the initial state before validation work is performed,
     * or a fallback state when DNSSEC is not applicable to the lookup path.
     */
    case INDETERMINATE = 'indeterminate';
}
