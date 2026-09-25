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
use ChiefTools\DNS\Resolver\Enums\LookupStatus;

$result = new Resolver()->resolve('example.com', 'A');

if ($result->status === LookupStatus::SUCCESS) {
    foreach ($result->records as $record) {
        echo "{$record->name} {$record->ttl} {$record->type->value} {$record->data}\n";
    }
}
```

## Interpreting results

`LookupResult::status` is the machine-readable outcome of the lookup. `info` is only a human-readable message for non-success cases.

```php
use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\Enums\LookupStatus;

$result = new Resolver()->resolve('example.com', 'A');

if ($result->status === LookupStatus::NXDOMAIN) {
    echo "The domain does not exist.\n";
} elseif ($result->status === LookupStatus::QUERY_FAILED) {
    echo "The lookup failed and may succeed on retry.\n";
} elseif ($result->status === LookupStatus::NO_RECORDS) {
    echo "The domain exists, but no records were found for that type.\n";
}

if ($result->isNxdomain()) {
    // Convenience helper for NXDOMAIN checks
}

if ($result->isLookupFailed()) {
    // Convenience helper for transport / nameserver failure checks
}

foreach ($result->records as $record) {
    echo $record->validation->name . "\n"; // SIGNED, FAILED, or UNKNOWN
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

## Checking authoritative nameservers

Enable source capture when you need to compare the answer from every nameserver in a parent delegation. The normal lookup still finishes first; call `verifyNameservers()` afterward, optionally with a callback to receive each nameserver answer as it arrives.

```php
use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\VerificationOptions;
use ChiefTools\DNS\Resolver\Results\NameserverAnswer;

$resolver = new Resolver();
$result = $resolver->resolve('www.example.com', ['A', 'AAAA'], captureAnswerSources: true);

foreach ($result->answerSources as $source) {
    echo "{$source->queryName} {$source->queryType} via {$source->selectedNameserver}\n";
    foreach ($source->nameservers as $nameserver) {
        echo "  {$nameserver->host}\n";
    }
}

$verification = $resolver->verifyNameservers(
    $result,
    static function (NameserverAnswer $answer): void {
        echo "{$answer->nameserver}: {$answer->status->value}\n";
    },
    new VerificationOptions(totalTimeout: 20),
);
```

Each record's `sourceId` links it to an `AnswerSource`. The verifier compares the complete record set for each captured query, ignoring record order and TTL. Its answers report matching, different, or unavailable nameservers, including missing and extra records. The aggregate source status is `agree`, `different`, `incomplete`, or `single`. An unavailable server does not count as agreement. `allowAddress` on `VerificationOptions` can restrict addresses used by the additional lookups.

The verifier uses a separate time budget from the initial lookup. With a deadline-aware executor, DNS waits share that budget; with other executors, the deadline is checked between blocking queries.

This compares the nameservers from the parent delegation observed during resolution. It does not use an NS record returned by the child zone as the authority list.

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

// Strict mode — clears records when validation fails
$result = new Resolver()->resolve('example.com', 'A', dnssec: DnssecMode::STRICT);

// Disable DNSSEC entirely
$result = new Resolver()->resolve('example.com', 'A', dnssec: DnssecMode::OFF);
```

## Configuration

```php
use ChiefTools\DNS\Resolver\ResolverConfig;

$resolver = new Resolver(
    config: new ResolverConfig(
        ipv6: false,     // Disable IPv6 for nameserver resolution (default: true)
        timeout: 5,      // Per-query timeout in seconds (default: 2)
        maxDepth: 15,    // Maximum recursive lookups (default: 10)
    ),
);
```

### Total timeout

Set `totalTimeout` to bound the complete DNS lookup, including delegation, nameserver fallback, CNAMEs, all requested record types, and DNSSEC queries. It accepts positive, finite seconds, including fractions. Its default is `null`, which preserves the existing per-query timeout behavior.

```php
use ChiefTools\DNS\Resolver\Resolver;
use ChiefTools\DNS\Resolver\ResolverConfig;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;

$resolver = new Resolver(config: new ResolverConfig(totalTimeout: 5));

try {
    $result = $resolver->resolve('client.example.test', ['A', 'AAAA']);
} catch (ResolutionTimeoutException $exception) {
    // The complete lookup exhausted its budget; no partial result is returned.
}
```

Each `resolve()` call starts a fresh monotonic deadline. The default executor bounds UDP and TCP connection, write, and read waits by the remaining time. TCP fallback and incremental responses share that budget. The existing per-query timeout still permits nameserver fallback while total time remains. DNS answers are not cached.

Event callbacks run synchronously and must remain nonblocking. The resolver checks its deadline before and after callbacks but cannot interrupt code inside them. Custom executors must also enforce the deadline during blocking operations.

Zone transfers (`AXFR` and `IXFR`) are not supported with `totalTimeout`; requesting them throws `InvalidArgumentException` before network activity.

## Custom executor

The resolver ships with `NetDns2QueryExecutor` (default) and `DigQueryExecutor`. You can provide your own by implementing the `DnsQueryExecutor` interface.

`DigQueryExecutor` requires external `dig` and `jc` binaries. If you do not need that integration, the default `NetDns2QueryExecutor` is the simpler and faster choice.

When `totalTimeout` is configured, the executor must implement `DeadlineAwareDnsQueryExecutor`. Its `queryWithDeadline()` method receives the same `ResolutionDeadline` throughout the lookup. Use `remaining()` to bound network waits and propagate `ResolutionTimeoutException` immediately. `DigQueryExecutor` and existing custom executors remain usable without a total timeout; configuring one with an executor that lacks deadline support throws `InvalidArgumentException` when constructing `Resolver`.

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
        // $event->type      — EventType enum (LOOKUP, QUERY, DELEGATION, CNAME, QUERY_FAILURE, NAMESERVER_FALLBACK, RESOLVE_NAMESERVER, RESOLVE_FAILURE)
        // $event->depth     — nesting level for visual indentation
        // $event->domain    — domain being queried
        // $event->nameserver, $event->address, $event->timeMs, etc.
        // $event->status    — per-step status such as "signed", "unsigned", "invalid", or null on non-query events
    },
);
```

## Result objects

### `LookupResult`

| Property | Type | Description |
|---|---|---|
| `records` | `list<Record>` | Resolved records |
| `timeMs` | `int` | Total resolution time in milliseconds |
| `status` | `LookupStatus` | Final lookup outcome: `SUCCESS`, `NO_RECORDS`, `NXDOMAIN`, or `QUERY_FAILED` |
| `info` | `?string` | Human-readable message for non-success outcomes or strict DNSSEC failures |
| `dnssec` | `?DnssecResult` | DNSSEC validation result (null when disabled) |

Methods: `isEmpty()`, `isNxdomain()`, `isLookupFailed()`, `ofType(RecordType|string)`

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
