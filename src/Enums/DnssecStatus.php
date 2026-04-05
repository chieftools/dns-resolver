<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum DnssecStatus: string
{
    case SIGNED        = 'signed';
    case UNSIGNED      = 'unsigned';
    case INVALID       = 'invalid';
    case INDETERMINATE = 'indeterminate';
}
