# DNS Resolver

A recursive DNS resolver for PHP with full DNSSEC validation. Performs iterative resolution from the root servers down, just like a real resolver — no reliance on the system stub resolver.

The intention of this package is to be a full non-caching resolver implementation. This allows stable and consistent results. It is not designed for latency critical applications or high query volumes. For those use cases, consider using a (local) caching resolver instead.

If you want to see the resolver in action, check out [dns.chief.tools](https://dns.chief.tools?ref=gh-package) — a free online DNS lookup tool built with this package.

## Requirements

- PHP 8.4+
- ext-openssl

## Installation

```bash
composer require chieftools/dns-resolver
```

## Quick start

```php
use ChiefTools\DNS\Resolver\Resolver;

$result = new Resolver()->resolve('example.com', 'A');

foreach ($result->records as $record) {
    echo "{$record->name} {$record->ttl} {$record->type->value} {$record->data}\n";
}
```

## Querying multiple types

Pass an array of types to resolve them in a single call. The resolver queries the authoritative server for each type once it reaches it, avoiding redundant delegation walks.

```php
use ChiefTools\DNS\Resolver\Resolver;

$result = new Resolver()->resolve('example.com', ['A', 'AAAA', 'MX']);

$aRecords = $result->ofType('A');
$mxRecords = $result->ofType(\ChiefTools\DNS\Resolver\Enums\RecordType::MX);
```

## DNSSEC validation

DNSSEC is enabled by default (`DnssecMode::ON`). The resolver validates the full chain of trust from the root zone trust anchor through every delegation.

```php
use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\DnssecMode;

// Validate and report — always returns results (default)
$result = new Resolver()->resolve('example.com', 'A', dnssec: DnssecMode::ON);

echo $result->dnssec->status->value; // "signed", "unsigned", "invalid", or "indeterminate"

// Per-record validation status
foreach ($result->records as $record) {
    echo $record->validation->name; // SIGNED, FAILED, or UNKNOWN
}

// Strict mode — returns empty results when validation fails
$result = $resolver->resolve('example.com', 'A', dnssec: DnssecMode::STRICT);

// Disable DNSSEC entirely
$result = $resolver->resolve('example.com', 'A', dnssec: DnssecMode::OFF);
```

## Configuration

```php
use ChiefTools\DNS\Resolver\ResolverConfig;

$resolver = new Resolver(
    config: new ResolverConfig(
        ipv6: false,     // Disable IPv6 for nameserver resolution (default: true)
        timeout: 5,      // Per-query timeout in seconds (default: 2)
        maxDepth: 15,    // Maximum delegation depth (default: 10)
    ),
);
```

## Custom executor

The resolver ships with `NetDns2QueryExecutor` (default) and `DigQueryExecutor`. You can provide your own by implementing the `DnsQueryExecutor` interface.

```php
use ChiefTools\DNS\Resolver\Executors\DigQueryExecutor;

$resolver = new Resolver(
    executor: new DigQueryExecutor(
        digPath: '/usr/local/bin/dig',
        jcPath: '/usr/local/bin/jc',
    ),
);
```

## Event callback

The `onEvent` callback fires synchronously during resolution, giving real-time visibility into every step. This is useful for streaming UIs, CLI progress output, or debug logging.

```php
use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Events\ResolverEvent;

$result = new Resolver()->resolve('example.com', 'A',
    onEvent: function (ResolverEvent $event) {
        // Pre-formatted message for simple output
        echo $event->message . "\n";

        // Or use structured data
        // $event->type      — EventType enum (LOOKUP, QUERY, DELEGATION, CNAME, ...)
        // $event->depth     — delegation depth (0 = root)
        // $event->domain    — domain being queried
        // $event->nameserver, $event->address, $event->timeMs, etc.
    },
);
```

## Result objects

### `LookupResult`

| Property | Type | Description |
|---|---|---|
| `records` | `list<Record>` | Resolved records |
| `timeMs` | `int` | Total resolution time in milliseconds |
| `info` | `?string` | Human-readable status (`"NXDOMAIN"`, etc.) |
| `dnssec` | `?DnssecResult` | DNSSEC validation result (null when disabled) |

Methods: `isEmpty()`, `isNxdomain()`, `ofType(RecordType|string)`

### `Record`

| Property | Type | Description |
|---|---|---|
| `name` | `string` | Owner name (e.g. `example.com.`) |
| `type` | `RecordType` | Record type enum |
| `ttl` | `int` | Time to live |
| `data` | `string` | Formatted record data |
| `rawData` | `string` | Original data as received from the nameserver |
| `validation` | `RecordValidation` | `SIGNED`, `FAILED`, or `UNKNOWN` |

### `DnssecResult`

| Property | Type | Description |
|---|---|---|
| `status` | `DnssecStatus` | `SIGNED`, `UNSIGNED`, `INVALID`, or `INDETERMINATE` |
| `errors` | `list<string>` | Validation error messages |

Methods: `isSigned()`, `isInvalid()`

## Supported record types

A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA, DS, DNSKEY, CDS, CDNSKEY, CSYNC, HTTPS, SVCB, DNAME, NAPTR, TLSA, SSHFP, SMIMEA, OPENPGPKEY, CERT, URI, LOC, SPF

## Security Vulnerabilities

If you discover a security vulnerability within this project, please report it privately via GitHub: https://github.com/chieftools/dns-resolver/security/advisories/new.
All security vulnerabilities will be swiftly addressed. There is no bug bounty program at this time.

## License

This package is open-source software licensed under the Apache License 2.0. This means you are free to use, modify, and distribute the software for both commercial and non-commercial purposes. See the [LICENSE](LICENSE) file for details.
