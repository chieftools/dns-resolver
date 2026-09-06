<?php

declare(strict_types=1);

use NetDNS2\RR;
use NetDNS2\Data;
use NetDNS2\Packet\Response;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$scenario = $argv[1];
$udp      = stream_socket_server('udp://127.0.0.1:0', $errorCode, $errorMessage, STREAM_SERVER_BIND);
$port     = (int)substr(strrchr(stream_socket_get_name($udp, false), ':'), 1);
$tcp      = stream_socket_server('tcp://127.0.0.1:' . $port, $errorCode, $errorMessage);
echo $port . PHP_EOL;
flush();

$client      = null;
$pending     = '';
$queryBuffer = '';
$nextByte    = 0;
$end         = hrtime(true) + 2_000_000_000;

while (hrtime(true) < $end) {
    $read = [$udp, $tcp];
    if (is_resource($client)) {
        $read[] = $client;
    }
    $write  = [];
    $except = [];
    stream_select($read, $write, $except, 0, 5_000);

    foreach ($read as $socket) {
        if ($socket === $tcp) {
            $client = stream_socket_accept($tcp, 0);
            stream_set_blocking($client, false);
            continue;
        }

        if ($socket === $client) {
            $queryBuffer .= fread($client, 65535);
            if (feof($client)) {
                echo 'closed' . PHP_EOL;
                flush();
                fclose($client);
                $client      = null;
                $pending     = '';
                $queryBuffer = '';
                continue;
            }
            if (strlen($queryBuffer) < 2) {
                continue;
            }
            $length = ord($queryBuffer[0]) * 256 + ord($queryBuffer[1]);
            if (strlen($queryBuffer) < $length + 2) {
                continue;
            }
            $query       = substr($queryBuffer, 2, $length);
            $queryBuffer = '';
        } else {
            $query = stream_socket_recvfrom($udp, 65535, 0, $peer);
        }

        if ($scenario === 'silent' || ($socket === $client && $scenario === 'tcp-stall')) {
            continue;
        }

        if ($socket === $client && $scenario === 'tcp-close') {
            fclose($client);
            $client = null;
            continue;
        }

        $response                  = new Response($query, strlen($query));
        $dnssec                    = count($response->additional) > 0 && $response->additional[0]->do === 1;
        $response->header->qr      = 1;
        $response->header->aa      = 1;
        $response->header->arcount = 0;
        $response->additional      = [];

        if ($socket === $udp && str_starts_with($scenario, 'tcp-')) {
            $response->header->tc = 1;
        } elseif ($scenario === 'nxdomain') {
            $response->header->rcode = NetDNS2\ENUM\RR\Code::NXDOMAIN;
        } else {
            $name                      = (string)$response->question[0]->qname;
            $record                    = $response->question[0]->qtype === NetDNS2\ENUM\RR\Type::AAAA ? 'AAAA 2001:db8::83' : 'A 192.0.2.83';
            $response->answer          = [RR::fromString($name . '. 60 IN ' . $record)];
            $response->header->ancount = 1;
        }

        if ($scenario === 'wrong-id') {
            $response->header->id = ($response->header->id + 1) % 65536;
        } elseif ($scenario === 'wrong-question') {
            $response->question[0]->qtype = NetDNS2\ENUM\RR\Type::AAAA;
        } elseif ($scenario === 'wrong-qr') {
            $response->header->qr = 0;
        } elseif ($scenario === 'wrong-opcode') {
            $response->header->opcode = NetDNS2\ENUM\OpCode::UPDATE;
        }

        Data::$compressed = [];
        $response->offset = 0;
        $bytes            = $response->get();
        echo 'query:' . $response->header->rd . ':' . (int)$dnssec . PHP_EOL;
        flush();

        if ($socket === $udp) {
            stream_socket_sendto($udp, $bytes, 0, $peer);
        } elseif ($scenario === 'tcp-trickle') {
            $pending  = pack('n', strlen($bytes)) . $bytes;
            $nextByte = hrtime(true);
        } else {
            fwrite($client, pack('n', strlen($bytes)) . $bytes);
            fclose($client);
            $client = null;
        }
    }

    if (is_resource($client) && $pending !== '' && hrtime(true) >= $nextByte) {
        @fwrite($client, $pending[0]);
        $pending  = substr($pending, 1);
        $nextByte = hrtime(true) + 15_000_000;
    }
}
