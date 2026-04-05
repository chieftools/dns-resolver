<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Enums;

enum RecordType: string
{
    case A          = 'A';
    case AAAA       = 'AAAA';
    case CNAME      = 'CNAME';
    case MX         = 'MX';
    case TXT        = 'TXT';
    case NS         = 'NS';
    case SOA        = 'SOA';
    case PTR        = 'PTR';
    case SRV        = 'SRV';
    case CAA        = 'CAA';
    case DS         = 'DS';
    case DNSKEY     = 'DNSKEY';
    case CDS        = 'CDS';
    case CDNSKEY    = 'CDNSKEY';
    case CSYNC      = 'CSYNC';
    case HTTPS      = 'HTTPS';
    case SVCB       = 'SVCB';
    case DNAME      = 'DNAME';
    case NAPTR      = 'NAPTR';
    case TLSA       = 'TLSA';
    case SSHFP      = 'SSHFP';
    case SMIMEA     = 'SMIMEA';
    case OPENPGPKEY = 'OPENPGPKEY';
    case CERT       = 'CERT';
    case URI        = 'URI';
    case LOC        = 'LOC';
    case SPF        = 'SPF';
}
