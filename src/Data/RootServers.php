<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Data;

final class RootServers
{
    /**
     * IANA root nameservers with IPv4 and IPv6 addresses.
     *
     * @return array<string, list<string>>
     */
    public static function all(): array
    {
        return [
            'a.root-servers.net' => ['198.41.0.4', '2001:503:ba3e::2:30'],
            'b.root-servers.net' => ['199.9.14.201', '2001:500:200::b'],
            'c.root-servers.net' => ['192.33.4.12', '2001:500:2::c'],
            'd.root-servers.net' => ['199.7.91.13', '2001:500:2d::d'],
            'e.root-servers.net' => ['192.203.230.10', '2001:500:a8::e'],
            'f.root-servers.net' => ['192.5.5.241', '2001:500:2f::f'],
            'g.root-servers.net' => ['192.112.36.4', '2001:500:12::d0d'],
            'h.root-servers.net' => ['198.97.190.53', '2001:500:1::53'],
            'i.root-servers.net' => ['192.36.148.17', '2001:7fe::53'],
            'j.root-servers.net' => ['192.58.128.30', '2001:503:c27::2:30'],
            'k.root-servers.net' => ['193.0.14.129', '2001:7fd::1'],
            'l.root-servers.net' => ['199.7.83.42', '2001:500:9f::42'],
            'm.root-servers.net' => ['202.12.27.33', '2001:dc3::35'],
        ];
    }

    /**
     * Get a random selection of root nameservers.
     *
     * @param bool $ipv6 Whether to include IPv6 addresses
     *
     * @return list<array{host: string, addr: string}>
     */
    public static function random(int $count = 3, bool $ipv6 = true): array
    {
        $roots = self::all();
        $keys  = array_keys($roots);

        shuffle($keys);

        $selected = array_slice($keys, 0, min($count, count($keys)));

        return array_map(static function (string $host) use ($roots, $ipv6): array {
            $addresses = $ipv6 ? $roots[$host] : [$roots[$host][0]];

            return [
                'host' => $host,
                'addr' => $addresses[array_rand($addresses)],
            ];
        }, $selected);
    }
}
