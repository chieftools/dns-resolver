<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Enums;

enum NameserverAnswerStatus: string
{
    case BASELINE    = 'baseline';
    case MATCH       = 'match';
    case DIFFERENT   = 'different';
    case UNAVAILABLE = 'unavailable';
}
