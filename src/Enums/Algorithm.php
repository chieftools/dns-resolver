<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum Algorithm: int
{
    case RSASHA1         = 5;
    case RSASHA1NSEC3    = 7;
    case RSASHA256       = 8;
    case RSASHA512       = 10;
    case ECDSAP256SHA256 = 13;
    case ECDSAP384SHA384 = 14;
    case ED25519         = 15;
}
