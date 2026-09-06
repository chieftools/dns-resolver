<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver\Executors;

use NetDNS2\Data;
use NetDNS2\Header;
use NetDNS2\RR\OPT;
use NetDNS2\Packet\Request;
use NetDNS2\Packet\Response;
use ChiefTools\DNS\Resolver\ResolutionDeadline;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;

/**
 * @internal NetDNS2 packet handling with bounded, nonblocking network IO.
 */
final class DeadlineAwareNetDns2Transport
{
    private readonly ResolutionDeadline $queryDeadline;

    public function __construct(
        private readonly ResolutionDeadline $deadline,
        private readonly string $nameserverAddr,
        float $timeout,
        private readonly bool $dnssec = false,
        private readonly int $port = 53,
    ) {
        if (filter_var($nameserverAddr, FILTER_VALIDATE_IP) === false) {
            throw new QueryException('A nameserver must be an IP address.');
        }

        $this->queryDeadline = $deadline->limit($timeout);
    }

    public function query(string $domain, string $type): Response
    {
        $this->remaining();
        if (in_array(strtoupper($type), ['AXFR', 'IXFR'], true)) {
            throw new QueryException('Zone transfers do not support a total timeout.');
        }

        Data::$compressed = [];
        $request             = new Request($domain, $type);
        $request->header->rd = 0;

        if ($this->dnssec) {
            $opt                      = new OPT;
            $opt->udp_length          = 4000;
            $opt->do                  = 1;
            $request->additional[]    = $opt;
            $request->header->arcount = 1;
        }

        $packet   = $request->get();
        $tcp      = strlen($packet) > ($this->dnssec ? 4000 : Header::DNS_MAX_UDP_SIZE);
        $response = $this->exchange($packet, $tcp);
        $this->validateHeader($request, $response);

        if (!$tcp && $response->header->tc === 1) {
            $response = $this->exchange($packet, true);
            $this->validateHeader($request, $response);
        }

        if ($response->header->tc === 1 || count($response->question) !== 1) {
            throw new QueryException('invalid response');
        }

        $question = $response->question[0];
        $expected = $request->question[0];

        if (
            strcasecmp(rtrim((string)$question->qname, '.'), rtrim((string)$expected->qname, '.')) !== 0
            || $question->qtype !== $expected->qtype
            || $question->qclass !== $expected->qclass
        ) {
            throw new QueryException('invalid response');
        }

        $this->remaining();

        return $response;
    }

    private function validateHeader(Request $request, Response $response): void
    {
        if (
            $response->header->id !== $request->header->id
            || $response->header->qr !== Header::QR_RESPONSE
            || $response->header->opcode !== $request->header->opcode
        ) {
            throw new QueryException('invalid response');
        }
    }

    private function exchange(string $packet, bool $tcp): Response
    {
        $this->remaining();
        $address  = str_contains($this->nameserverAddr, ':') ? '[' . $this->nameserverAddr . ']' : $this->nameserverAddr;
        $protocol = $tcp ? 'tcp' : 'udp';
        $socket   = @stream_socket_client(
            "{$protocol}://{$address}:{$this->port}",
            $errorCode,
            $errorMessage,
            0,
            STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT,
        );

        if ($socket === false) {
            throw new QueryException('connection error');
        }

        try {
            stream_set_blocking($socket, false);
            $data = $tcp ? pack('n', strlen($packet)) . $packet : $packet;

            do {
                $this->wait($socket, false);
                $written = @fwrite($socket, $data);

                if ($written === false || $written === 0 || (!$tcp && $written !== strlen($data))) {
                    throw new QueryException('connection error');
                }

                $data = substr($data, $written);
            } while ($data !== '');

            if ($tcp) {
                $prefix = $this->readExactly($socket, 2);
                $length = ord($prefix[0]) * 256 + ord($prefix[1]);

                if ($length < Header::DNS_HEADER_SIZE) {
                    throw new QueryException('invalid response');
                }

                $data = $this->readExactly($socket, $length);
            } else {
                $this->wait($socket, true);
                $data = @fread($socket, 65535);

                if ($data === false || $data === '') {
                    throw new QueryException('connection error');
                }
            }

            $this->remaining();
            $response = new Response($data, strlen($data));
            $this->remaining();

            return $response;
        } finally {
            fclose($socket);
        }
    }

    /** @param resource $socket */
    private function readExactly(mixed $socket, int $length): string
    {
        $data = '';

        while (strlen($data) < $length) {
            $this->wait($socket, true);
            $chunk = @fread($socket, max(1, $length - strlen($data)));

            if ($chunk === false || $chunk === '') {
                throw new QueryException('connection error');
            }

            $data .= $chunk;
        }

        return $data;
    }

    /** @param resource $socket */
    private function wait(mixed $socket, bool $reading): void
    {
        $remaining        = $this->remaining();
        $read             = $reading ? [$socket] : [];
        $write            = $reading ? [] : [$socket];
        $except           = [];
        $waitMicroseconds = (int)ceil($remaining * 1_000_000);
        $seconds          = intdiv($waitMicroseconds, 1_000_000);
        $microseconds     = $waitMicroseconds % 1_000_000;

        $ready = @stream_select($read, $write, $except, $seconds, $microseconds);

        if ($ready === false) {
            throw new QueryException('connection error');
        }

        $this->remaining();

        if ($ready === 0) {
            throw new QueryException('timeout');
        }
    }

    private function remaining(): float
    {
        $remaining = $this->deadline->remaining();

        try {
            return min($remaining, $this->queryDeadline->remaining());
        } catch (ResolutionTimeoutException) {
            $this->deadline->throwIfExpired();
            throw new QueryException('timeout');
        }
    }
}
