<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Events;

enum EventType
{
    case LOOKUP;              // Starting lookup at a nameserver
    case QUERY;               // Query completed (with or without answers)
    case DELEGATION;          // NS delegation received, recursing deeper
    case CNAME;               // Following CNAME to target
    case QUERY_FAILURE;       // Query to nameserver failed (timeout, etc.)
    case NAMESERVER_FALLBACK; // Trying next nameserver after failure
    case RESOLVE_NAMESERVER;  // Resolving a nameserver's IP (no glue)
    case RESOLVE_FAILURE;     // Failed to resolve nameserver IP
}
