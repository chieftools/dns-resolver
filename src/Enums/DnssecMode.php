<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum DnssecMode
{
    case OFF;       // No validation
    case ON;        // Validate and report, always return results
    case STRICT;    // Validate and fail if invalid
}
