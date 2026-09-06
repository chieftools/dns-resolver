<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Tests\Support;

use RuntimeException;

final class LocalDnsServer
{
    /** @var resource */
    private mixed $process;

    /** @var array<int, resource> */
    private array $pipes;

    public readonly int $port;

    public function __construct(string $scenario)
    {
        $process = proc_open([PHP_BINARY, __DIR__ . '/dns-server.php', $scenario], [
            0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
        ], $pipes);

        if ($process === false) {
            throw new RuntimeException('Unable to start the local DNS fixture.');
        }

        $this->process = $process;
        $this->pipes   = $pipes;
        stream_set_timeout($pipes[1], 3);
        $port = fgets($pipes[1]);

        if ($port === false || (int)$port < 1) {
            $this->stop();
            throw new RuntimeException('The local DNS fixture did not start.');
        }

        $this->port = (int)$port;
    }

    public function output(): string
    {
        stream_set_blocking($this->pipes[1], false);

        return stream_get_contents($this->pipes[1]);
    }

    public function waitForClose(): string
    {
        $output = $this->output();
        $end    = hrtime(true) + 100_000_000;

        while (!str_contains($output, 'closed') && hrtime(true) < $end) {
            $read   = [$this->pipes[1]];
            $write  = [];
            $except = [];
            stream_select($read, $write, $except, 0, 10_000);
            $output .= $this->output();
        }

        return $output;
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process, 9);
            foreach ($this->pipes as $pipe) {
                fclose($pipe);
            }
            proc_close($this->process);
        }
    }

    public function __destruct()
    {
        $this->stop();
    }
}
