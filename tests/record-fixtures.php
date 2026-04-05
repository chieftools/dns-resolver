<?php

declare(strict_types=1);

/**
 * Run this script to record fresh fixtures for integration tests.
 *
 * Usage: php tests/record-fixtures.php
 */

require __DIR__ . '/../vendor/autoload.php';

use ChiefTools\DNS\Resolver\Tests\Support\FixtureRecorder;
use ChiefTools\DNS\Resolver\Executors\NetDns2QueryExecutor;

$executor   = new NetDns2QueryExecutor;
$fixtureDir = __DIR__ . '/Fixtures';

// Simple A record (example.com)
echo "Recording: simple A record (example.com)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('example.com', ['A']);
$recorder->save("{$fixtureDir}/simple-a-record.json");

// Multi-type query (example.com A + AAAA + MX)
echo "Recording: multi-type query (example.com)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('example.com', ['A', 'AAAA', 'MX']);
$recorder->save("{$fixtureDir}/multi-type-query.json");

// CNAME following (github.com → A)
echo "Recording: CNAME following (www.github.com)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('www.github.com', ['A', 'CNAME']);
$recorder->save("{$fixtureDir}/cname-following.json");

// DNSSEC-signed zone (cloudflare.com)
echo "Recording: DNSSEC-signed zone (cloudflare.com)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('cloudflare.com', ['A', 'AAAA'], dnssec: true);
$recorder->save("{$fixtureDir}/wildcard-dnssec.json");

// Unsigned zone (example.com - not DNSSEC signed)
echo "Recording: unsigned zone (example.com)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('example.com', ['A'], dnssec: true);
$recorder->save("{$fixtureDir}/unsigned-zone.json");

// NXDOMAIN
echo "Recording: NXDOMAIN (thisdoesnotexist.example.com)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('thisdoesnotexist.example.com', ['A']);
$recorder->save("{$fixtureDir}/nxdomain.json");

// Nameserver resolution (delegation without glue)
echo "Recording: nameserver resolution (github.com NS)...\n";
$recorder = new FixtureRecorder($executor);
$recorder->record('github.com', ['A', 'NS']);
$recorder->save("{$fixtureDir}/nameserver-resolution.json");

echo "Done! All fixtures recorded.\n";
