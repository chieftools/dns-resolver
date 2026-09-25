<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Enums;

enum NameserverVerificationStatus: string
{
    case AGREE      = 'agree';
    case DIFFERENT  = 'different';
    case INCOMPLETE = 'incomplete';
    case SINGLE     = 'single';
}
