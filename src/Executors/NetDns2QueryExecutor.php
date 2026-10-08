<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Executors;

use NetDNS2\RR;
use NetDNS2\RR\OPT;
use NetDNS2\Resolver;
use NetDNS2\Exception;
use ChiefTools\DNS\Resolver\ResolutionDeadline;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;

class NetDns2QueryExecutor implements DeadlineAwareDnsQueryExecutor
{
    /**
     * The EDNS(0) UDP payload size we advertise, as recommended by DNS Flag Day 2020.
     *
     * Larger UDP answers get fragmented and fragments are often dropped, which causes timeouts.
     * Answers that don't fit are truncated and retried over TCP instead.
     */
    public const int UDP_PAYLOAD_SIZE = 1232;

    public function __construct(
        private readonly int $timeout = 2,
        private readonly int $port = 53,
    ) {}

    public function query(string $domain, string $type, string $nameserverAddr, bool $dnssec = false): QueryResult
    {
        $result = $this->execute($this->createResolver($nameserverAddr, $dnssec, edns: true), $domain, $type);

        // Some nameservers answer EDNS queries with FORMERR, RFC 6891 section 7 says to retry those without EDNS
        if ($result->responseCode === 'FORMERR') {
            return $this->execute($this->createResolver($nameserverAddr, dnssec: false, edns: false), $domain, $type);
        }

        return $result;
    }

    public function queryWithDeadline(
        string $domain,
        string $type,
        string $nameserverAddr,
        bool $dnssec,
        ResolutionDeadline $deadline,
    ): QueryResult {
        $deadline->throwIfExpired();

        $resolver = new DeadlineAwareNetDns2Transport($deadline, $nameserverAddr, $this->timeout, $dnssec, $this->port);
        $result   = $this->execute($resolver, $domain, $type);
        $deadline->throwIfExpired();

        return $result;
    }

    private function createResolver(string $nameserverAddr, bool $dnssec, bool $edns): Resolver
    {
        try {
            $resolver = new Resolver([
                'nameservers' => [$nameserverAddr],
                'recurse'     => false,
                'timeout'     => $this->timeout,
                'dnssec'      => $dnssec,
                'dns_port'    => $this->port,
                'cache_type'  => \NetDNS2\Cache::CACHE_TYPE_NONE,
            ]);
        } catch (Exception $e) {
            throw new QueryException(self::mapErrorMessage($e->getMessage()), previous: $e);
        }

        // Use EDNS(0) so answers larger than 512 bytes fit over UDP, not every nameserver answers over TCP.
        // NetDNS2 only adds an OPT record when an EDNS option is set, a bare OPT record enables EDNS without the DO bit.
        if ($edns && !$dnssec) {
            $resolver->edns->opts['edns'] = new OPT;
        }

        $resolver->dnssec_payload_size = self::UDP_PAYLOAD_SIZE;

        return $resolver;
    }

    private function execute(Resolver|DeadlineAwareNetDns2Transport $resolver, string $domain, string $type): QueryResult
    {
        $startTime = hrtime(true);

        try {
            $response = $resolver->query($domain, $type);
        } catch (Exception $e) {
            $queryTime = (int)((hrtime(true) - $startTime) / 1_000_000);

            $response = $e->getResponse();

            if ($response === null) {
                throw new QueryException(self::mapErrorMessage($e->getMessage()), previous: $e);
            }

            return new QueryResult(
                answer: $this->convertSection($response->answer),
                authority: $this->convertSection($response->authority),
                additional: $this->convertSection($response->additional),
                queryTimeMs: $queryTime,
                responseCode: $response->header->rcode->name,
            );
        }

        $queryTime = (int)((hrtime(true) - $startTime) / 1_000_000);

        return new QueryResult(
            answer: $this->convertSection($response->answer),
            authority: $this->convertSection($response->authority),
            additional: $this->convertSection($response->additional),
            queryTimeMs: $queryTime,
            responseCode: $response->header->rcode->name,
        );
    }

    private static function mapErrorMessage(string $message): string
    {
        $message = strtolower($message);

        return match (true) {
            str_contains($message, 'timeout')                         => 'timeout',
            str_contains($message, 'failed to connect')
            || str_contains($message, 'connection refused')
            || str_contains($message, 'failed to build valid server') => 'connection refused',
            str_contains($message, 'fread()')
            || str_contains($message, 'fwrite()')
            || str_contains($message, 'empty data')
            || str_contains($message, 'select()')                     => 'connection error',
            default                                                   => 'query failed',
        };
    }

    /**
     * Convert a section of NetDNS2 RR objects to RawRecord DTOs.
     *
     * @param array<\NetDNS2\RR> $section
     *
     * @return list<RawRecord>
     */
    private function convertSection(array $section): array
    {
        $records = [];

        foreach ($section as $rr) {
            $type = $rr->type->label();

            if ($type === 'OPT') {
                continue;
            }

            $data = $this->extractRdata($rr, $type);

            $records[] = new RawRecord(
                name: strval($rr->name) . '.',
                class: $rr->class->label(),
                type: $type,
                ttl: $rr->ttl,
                data: $data,
            );
        }

        return $records;
    }

    /** Extract the RDATA presentation string from an RR object. */
    private function extractRdata(RR $rr, string $type): string
    {
        $fullString = (string)$rr;

        $prefix = strval($rr->name) . '. ' . $rr->ttl . ' ' . $rr->class->label() . ' ' . $type . ' ';

        $data = substr($fullString, strlen($prefix));

        if (($type === 'TXT' || $type === 'SPF') && str_starts_with($data, '"') && str_ends_with($data, '"')) {
            $data = substr($data, 1, -1);
        }

        if ($type === 'NSEC3') {
            $data = $this->convertNsec3HashEncoding($data);
        }

        return $data;
    }

    /** Convert NSEC3 hashed owner name from base64 (NetDNS2) to base32hex (dig). */
    private function convertNsec3HashEncoding(string $data): string
    {
        $parts = preg_split('/\s+/', $data, 6);

        if ($parts === false || count($parts) < 5) {
            return $data;
        }

        $binary = base64_decode($parts[4], true);

        if ($binary === false) {
            return $data;
        }

        $parts[4] = rtrim(self::base32HexEncode($binary), '=');

        return implode(' ', $parts);
    }

    /** Encode binary data as base32hex (RFC 4648 Section 7). */
    private static function base32HexEncode(string $data): string
    {
        $alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        $result   = '';
        $buffer   = 0;
        $bits     = 0;

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $buffer  = ($buffer << 8) | ord($data[$i]);
            $bits   += 8;

            while ($bits >= 5) {
                $bits   -= 5;
                $result .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }

        if ($bits > 0) {
            $result .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }

        return $result;
    }
}
