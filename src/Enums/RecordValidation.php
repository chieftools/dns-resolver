<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum RecordValidation
{
    case SIGNED;    // RRSIG verified successfully
    case FAILED;    // RRSIG verification failed
    case UNKNOWN;   // No RRSIG present or DNSSEC not enabled
}
