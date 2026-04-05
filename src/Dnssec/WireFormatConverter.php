<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Dnssec;

/**
 * Converts DNS record data to wire format for DNSSEC signature verification.
 *
 * This class handles the conversion of human-readable DNS record data (as output by dig)
 * to the canonical wire format required for RRSIG verification (RFC 4034).
 */
readonly class WireFormatConverter
{
    /**
     * DNS record type codes.
     *
     * @var array<string, int>
     */
    private const array TYPE_CODES = [
        'A'          => 1,
        'NS'         => 2,
        'CNAME'      => 5,
        'SOA'        => 6,
        'PTR'        => 12,
        'HINFO'      => 13,
        'MX'         => 15,
        'TXT'        => 16,
        'AAAA'       => 28,
        'LOC'        => 29,
        'SRV'        => 33,
        'NAPTR'      => 35,
        'CERT'       => 37,
        'DNAME'      => 39,
        'DS'         => 43,
        'SSHFP'      => 44,
        'RRSIG'      => 46,
        'NSEC'       => 47,
        'DNSKEY'     => 48,
        'NSEC3'      => 50,
        'NSEC3PARAM' => 51,
        'TLSA'       => 52,
        'SMIMEA'     => 53,
        'HIP'        => 55,
        'CDS'        => 59,
        'CDNSKEY'    => 60,
        'OPENPGPKEY' => 61,
        'CSYNC'      => 62,
        'ZONEMD'     => 63,
        'SVCB'       => 64,
        'HTTPS'      => 65,
        'SPF'        => 99,
        'NXNAME'     => 128,
        'URI'        => 256,
        'CAA'        => 257,
    ];

    /**
     * Convert RDATA to wire format based on record type.
     */
    public function rdataToWire(string $type, string $data): ?string
    {
        return match ($type) {
            // Address records
            'A'                           => $this->ipv4ToWire($data),
            'AAAA'                        => $this->ipv6ToWire($data),

            // Name records (just a domain name)
            'NS', 'CNAME', 'PTR', 'DNAME' => $this->nameToWire($data),

            // Common records
            'MX'                          => $this->mxToWire($data),
            'TXT', 'SPF'                  => $this->txtToWire($data),
            'SOA'                         => $this->soaToWire($data),
            'SRV'                         => $this->srvToWire($data),
            'CAA'                         => $this->caaToWire($data),
            'NAPTR'                       => $this->naptrToWire($data),
            'LOC'                         => $this->locToWire($data),

            // DNSSEC records
            'DNSKEY', 'CDNSKEY'           => $this->dnskeyToWire($data),
            'DS', 'CDS'                   => $this->dsToWire($data),
            'NSEC'                        => $this->nsecToWire($data),
            'NSEC3'                       => $this->nsec3ToWire($data),
            'CSYNC'                       => $this->csyncToWire($data),

            // Security records
            'SSHFP'                       => $this->sshfpToWire($data),
            'TLSA', 'SMIMEA'              => $this->tlsaToWire($data),
            'OPENPGPKEY'                  => $this->openpgpkeyToWire($data),
            'CERT'                        => $this->certToWire($data),

            // Service binding records
            'SVCB', 'HTTPS'               => $this->svcbToWire($data),

            // URI record
            'URI'                         => $this->uriToWire($data),

            default                       => null,
        };
    }

    /**
     * Convert a domain name to DNS wire format.
     *
     * Example: "example.com" -> "\x07example\x03com\x00"
     *
     * Handles dig escape sequences like \DDD (octal) for binary data in labels.
     */
    public function nameToWire(string $name): string
    {
        if ($name === '' || $name === '.') {
            return "\x00";
        }

        $name   = strtolower(rtrim($name, '.'));
        $labels = explode('.', $name);
        $wire   = '';

        foreach ($labels as $label) {
            $decodedLabel = $this->decodeDnsLabel($label);
            $wire .= chr(strlen($decodedLabel) & 0xFF) . $decodedLabel;
        }

        return $wire . "\x00";
    }

    /**
     * Get DNS type code from type name.
     *
     * Also handles TYPEnn format (e.g., TYPE64, TYPE65).
     */
    public function getTypeCode(string $type): ?int
    {
        $upperType = strtoupper($type);

        if (isset(self::TYPE_CODES[$upperType])) {
            return self::TYPE_CODES[$upperType];
        }

        // Handle TYPEnn format (e.g., TYPE64, TYPE65)
        if (preg_match('/^TYPE(\d+)$/i', $type, $matches)) {
            return (int)$matches[1];
        }

        return null;
    }

    /**
     * Build type bitmap for NSEC/NSEC3 records.
     *
     * The type bitmap format is defined in RFC 4034 Section 4.1.2.
     *
     * @param array<string> $typeList List of type names (e.g., ['A', 'NS', 'MX'])
     */
    public function buildTypeBitmap(array $typeList): string
    {
        // Group types by window (high byte of type code)
        $windows = [];

        foreach ($typeList as $typeName) {
            $typeCode = $this->getTypeCode($typeName);

            if ($typeCode === null) {
                continue;
            }

            $window = ($typeCode >> 8) & 0xFF;
            $offset = $typeCode & 0xFF;

            if (!isset($windows[$window])) {
                $windows[$window] = [];
            }

            $windows[$window][$offset] = true;
        }

        ksort($windows);

        $wire = '';

        foreach ($windows as $window => $bits) {
            $maxBit   = max(array_keys($bits));
            $numBytes = (int)(($maxBit / 8) + 1);
            $bitmap   = str_repeat("\x00", $numBytes);

            foreach ($bits as $bitPos => $set) {
                $byteIndex          = (int)($bitPos / 8);
                $bitIndex           = 7 - ($bitPos % 8);
                $bitmap[$byteIndex] = chr((ord($bitmap[$byteIndex]) | (1 << $bitIndex)) & 0xFF);
            }

            $wire .= chr($window & 0xFF) . chr($numBytes & 0xFF) . $bitmap;
        }

        return $wire;
    }

    /**
     * Decode base32hex encoded string (RFC 4648 Section 7).
     */
    public function base32Decode(string $encoded): ?string
    {
        $alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

        $encoded = strtoupper(rtrim($encoded, '='));
        $len     = strlen($encoded);
        $buffer  = 0;
        $bits    = 0;
        $result  = '';

        for ($i = 0; $i < $len; $i++) {
            $char = $encoded[$i];
            $val  = strpos($alphabet, $char);

            if ($val === false) {
                return null;
            }

            $buffer = ($buffer << 5) | $val;
            $bits += 5;

            if ($bits >= 8) {
                $bits -= 8;
                $result .= chr(($buffer >> $bits) & 0xFF);
            }
        }

        return $result;
    }

    /**
     * Decode a DNS label that may contain dig escape sequences.
     */
    private function decodeDnsLabel(string $label): string
    {
        $result = '';
        $len    = strlen($label);
        $i      = 0;

        while ($i < $len) {
            if ($label[$i] === '\\' && $i + 1 < $len) {
                if ($i + 3 < $len && ctype_digit($label[$i + 1]) && ctype_digit($label[$i + 2]) && ctype_digit($label[$i + 3])) {
                    $octal  = substr($label, $i + 1, 3);
                    $result .= chr(((int)octdec($octal)) & 0xFF);
                    $i += 4;
                } else {
                    $result .= $label[$i + 1];
                    $i += 2;
                }
            } else {
                $result .= $label[$i];
                $i++;
            }
        }

        return $result;
    }

    private function ipv4ToWire(string $ip): ?string
    {
        $packed = inet_pton($ip);

        return $packed !== false && strlen($packed) === 4 ? $packed : null;
    }

    private function ipv6ToWire(string $ip): ?string
    {
        $packed = inet_pton($ip);

        return $packed !== false && strlen($packed) === 16 ? $packed : null;
    }

    private function mxToWire(string $data): ?string
    {
        if (!preg_match('/^(\d+)\s+(\S+)$/', $data, $matches)) {
            return null;
        }

        return pack('n', (int)$matches[1]) . $this->nameToWire($matches[2]);
    }

    private function txtToWire(string $data): string
    {
        $strings = explode('" "', $data);
        $result  = '';

        foreach ($strings as $string) {
            $string = trim($string, '"');

            while (strlen($string) > 255) {
                $result .= chr(255) . substr($string, 0, 255);
                $string = substr($string, 255);
            }

            $result .= chr(strlen($string) & 0xFF) . $string;
        }

        return $result;
    }

    private function soaToWire(string $data): ?string
    {
        $parts = preg_split('/\s+/', $data);

        if ($parts === false || count($parts) < 7) {
            return null;
        }

        return $this->nameToWire($parts[0])
               . $this->nameToWire($parts[1])
               . pack('NNNNN', (int)$parts[2], (int)$parts[3], (int)$parts[4], (int)$parts[5], (int)$parts[6]);
    }

    private function dnskeyToWire(string $data): ?string
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/s', $data, $matches)) {
            return null;
        }

        $publicKey = base64_decode(preg_replace('/\s+/', '', $matches[4]) ?? '', true);

        if ($publicKey === false) {
            return null;
        }

        return pack('nCC', (int)$matches[1], (int)$matches[2], (int)$matches[3]) . $publicKey;
    }

    private function dsToWire(string $data): ?string
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f\s]+)$/', $data, $matches)) {
            return null;
        }

        $digest = hex2bin(preg_replace('/\s+/', '', $matches[4]) ?? '');

        if ($digest === false) {
            return null;
        }

        return pack('nCC', (int)$matches[1], (int)$matches[2], (int)$matches[3]) . $digest;
    }

    private function srvToWire(string $data): ?string
    {
        if (!preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$/', $data, $matches)) {
            return null;
        }

        return pack('nnn', (int)$matches[1], (int)$matches[2], (int)$matches[3])
               . $this->nameToWire($matches[4]);
    }

    private function caaToWire(string $data): ?string
    {
        if (!preg_match('/^(\d+)\s+(\S+)\s+"?([^"]*)"?$/', $data, $matches)) {
            return null;
        }

        $flags = (int)$matches[1];
        $tag   = $matches[2];
        $value = $matches[3];

        return pack('CC', $flags, strlen($tag)) . $tag . $value;
    }

    private function naptrToWire(string $data): ?string
    {
        if (!preg_match('/^(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+(\S+)$/', $data, $matches)) {
            return null;
        }

        $order       = (int)$matches[1];
        $preference  = (int)$matches[2];
        $flags       = $matches[3];
        $service     = $matches[4];
        $regexp      = $matches[5];
        $replacement = $matches[6];

        return pack('nn', $order, $preference)
               . chr(strlen($flags) & 0xFF) . $flags
               . chr(strlen($service) & 0xFF) . $service
               . chr(strlen($regexp) & 0xFF) . $regexp
               . $this->nameToWire($replacement);
    }

    private function sshfpToWire(string $data): ?string
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\d+)\s+(\d+)\s+([0-9A-Fa-f\s]+)$/', $data, $matches)) {
            return null;
        }

        $fingerprint = hex2bin(preg_replace('/\s+/', '', $matches[3]) ?? '');

        if ($fingerprint === false) {
            return null;
        }

        return pack('CC', (int)$matches[1], (int)$matches[2]) . $fingerprint;
    }

    private function tlsaToWire(string $data): ?string
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f\s]+)$/', $data, $matches)) {
            return null;
        }

        $certData = hex2bin(preg_replace('/\s+/', '', $matches[4]) ?? '');

        if ($certData === false) {
            return null;
        }

        return pack('CCC', (int)$matches[1], (int)$matches[2], (int)$matches[3]) . $certData;
    }

    /**
     * Convert LOC record to wire format (RFC 1876).
     */
    private function locToWire(string $data): ?string
    {
        $pattern = '/^(\d+)\s+(\d+)\s+([\d.]+)\s+([NS])\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([EW])\s+([-\d.]+)m(?:\s+([\d.]+)m)?(?:\s+([\d.]+)m)?(?:\s+([\d.]+)m)?$/';

        if (!preg_match($pattern, $data, $matches)) {
            return null;
        }

        $latDeg = (int)$matches[1];
        $latMin = (int)$matches[2];
        $latSec = (float)$matches[3];
        $latDir = $matches[4];

        $latitude = ($latDeg * 3600 + $latMin * 60 + $latSec) * 1000;
        if ($latDir === 'S') {
            $latitude = -$latitude;
        }
        $latitude = (int)($latitude + 2147483648);

        $longDeg = (int)$matches[5];
        $longMin = (int)$matches[6];
        $longSec = (float)$matches[7];
        $longDir = $matches[8];

        $longitude = ($longDeg * 3600 + $longMin * 60 + $longSec) * 1000;
        if ($longDir === 'W') {
            $longitude = -$longitude;
        }
        $longitude = (int)($longitude + 2147483648);

        $altMeters = (float)$matches[9];
        $altitude  = (int)(($altMeters * 100) + 10000000);

        $size     = ($matches[10] ?? '') !== '' ? $this->locPrecisionToWire((float)$matches[10]) : 0x12;
        $horizPre = ($matches[11] ?? '') !== '' ? $this->locPrecisionToWire((float)$matches[11]) : 0x16;
        $vertPre  = ($matches[12] ?? '') !== '' ? $this->locPrecisionToWire((float)$matches[12]) : 0x13;

        return pack('CCCCNNN', 0, $size, $horizPre, $vertPre, $latitude, $longitude, $altitude);
    }

    private function locPrecisionToWire(float $meters): int
    {
        $cm = (int)($meters * 100);

        if ($cm <= 0) {
            return 0x00;
        }

        $exp = 0;
        $val = $cm;

        while ($val >= 10 && $exp < 9) {
            $val = (int)($val / 10);
            $exp++;
        }

        $mantissa = min(9, max(0, $val));

        return ($mantissa << 4) | $exp;
    }

    private function nsecToWire(string $data): ?string
    {
        $parts = preg_split('/\s+/', trim($data, " \t\n\r\x0B"), 2);

        if ($parts === false || count($parts) < 2) {
            return null;
        }

        $nextDomain = $parts[0];
        $typeList   = preg_split('/\s+/', trim($parts[1], " \t\n\r\x0B"));

        if ($typeList === false) {
            return null;
        }

        return $this->nameToWire($nextDomain) . $this->buildTypeBitmap($typeList);
    }

    /**
     * Convert NSEC3 record to wire format (RFC 5155).
     */
    private function nsec3ToWire(string $data): ?string
    {
        $parts = preg_split('/\s+/', trim($data));

        if ($parts === false || count($parts) < 5) {
            return null;
        }

        $algorithm  = (int)$parts[0];
        $flags      = (int)$parts[1];
        $iterations = (int)$parts[2];
        $saltHex    = $parts[3];
        $nextHash   = $parts[4];
        $typeList   = array_slice($parts, 5);

        $wire = pack('CCn', $algorithm, $flags, $iterations);

        if ($saltHex === '-') {
            $wire .= "\x00";
        } else {
            $salt = hex2bin($saltHex);

            if ($salt === false) {
                return null;
            }

            $wire .= chr(strlen($salt) & 0xFF) . $salt;
        }

        $nextHashBinary = $this->base32Decode($nextHash);

        if ($nextHashBinary === null) {
            return null;
        }

        $wire .= chr(strlen($nextHashBinary) & 0xFF) . $nextHashBinary;

        $wire .= $this->buildTypeBitmap($typeList);

        return $wire;
    }

    /**
     * Convert CSYNC record to wire format (RFC 7477).
     */
    private function csyncToWire(string $data): ?string
    {
        $parts = preg_split('/\s+/', trim($data));

        if ($parts === false || count($parts) < 2) {
            return null;
        }

        $soaSerial = (int)$parts[0];
        $flags     = (int)$parts[1];
        $typeList  = array_slice($parts, 2);

        return pack('Nn', $soaSerial, $flags) . $this->buildTypeBitmap($typeList);
    }

    private function openpgpkeyToWire(string $data): ?string
    {
        $data      = preg_replace('/\s+/', '', trim($data));
        $publicKey = base64_decode($data ?? '', true);

        return $publicKey !== false ? $publicKey : null;
    }

    /**
     * Convert CERT record to wire format (RFC 4398).
     */
    private function certToWire(string $data): ?string
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\S+)\s+(\d+)\s+(\d+)\s+(.+)$/s', $data, $matches)) {
            return null;
        }

        $certType = $this->getCertTypeCode($matches[1]);

        if ($certType === null) {
            return null;
        }

        $keyTag    = (int)$matches[2];
        $algorithm = (int)$matches[3];
        $certData  = base64_decode(preg_replace('/\s+/', '', $matches[4]) ?? '', true);

        if ($certData === false) {
            return null;
        }

        return pack('nnC', $certType, $keyTag, $algorithm) . $certData;
    }

    private function getCertTypeCode(string $type): ?int
    {
        if (is_numeric($type)) {
            return (int)$type;
        }

        return match (strtoupper($type)) {
            'PKIX'    => 1,
            'SPKI'    => 2,
            'PGP'     => 3,
            'IPKIX'   => 4,
            'ISPKI'   => 5,
            'IPGP'    => 6,
            'ACPKIX'  => 7,
            'IACPKIX' => 8,
            'URI'     => 253,
            'OID'     => 254,
            default   => null,
        };
    }

    /**
     * Convert SVCB/HTTPS record to wire format (RFC 9460).
     */
    private function svcbToWire(string $data): ?string
    {
        $parts = preg_split('/\s+/', trim($data), 3);

        if ($parts === false || count($parts) < 2) {
            return null;
        }

        $priority = (int)$parts[0];
        $target   = $parts[1];
        $params   = $parts[2] ?? '';

        $wire = pack('n', $priority) . $this->nameToWire($target);

        if ($params !== '') {
            $wire .= $this->svcParamsToWire($params);
        }

        return $wire;
    }

    private function svcParamsToWire(string $params): string
    {
        $parsedParams = [];

        preg_match_all('/(\w+)=(?:"([^"]*)"|(\S+))/', $params, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $key   = strtolower($match[1]);
            $value = ($match[2] ?? '') !== '' ? $match[2] : ($match[3] ?? '');

            $keyCode = $this->getSvcParamKey($key);

            if ($keyCode === null) {
                continue;
            }

            $valueWire = $this->svcParamValueToWire($key, $value);

            if ($valueWire !== null) {
                $parsedParams[$keyCode] = $valueWire;
            }
        }

        ksort($parsedParams);

        $wire = '';

        foreach ($parsedParams as $keyCode => $valueWire) {
            $wire .= pack('nn', $keyCode, strlen($valueWire)) . $valueWire;
        }

        return $wire;
    }

    private function getSvcParamKey(string $key): ?int
    {
        return match ($key) {
            'mandatory'       => 0,
            'alpn'            => 1,
            'no-default-alpn' => 2,
            'port'            => 3,
            'ipv4hint'        => 4,
            'ech'             => 5,
            'ipv6hint'        => 6,
            default           => null,
        };
    }

    private function svcParamValueToWire(string $key, string $value): ?string
    {
        return match ($key) {
            'alpn'            => $this->alpnToWire($value),
            'no-default-alpn' => '',
            'port'            => pack('n', (int)$value),
            'ipv4hint'        => $this->ipv4HintToWire($value),
            'ipv6hint'        => $this->ipv6HintToWire($value),
            'ech'             => base64_decode($value, true) ?: null,
            default           => null,
        };
    }

    private function alpnToWire(string $value): string
    {
        $wire    = '';
        $alpnIds = explode(',', $value);

        foreach ($alpnIds as $alpnId) {
            $alpnId = trim($alpnId);
            $wire .= chr(strlen($alpnId) & 0xFF) . $alpnId;
        }

        return $wire;
    }

    private function ipv4HintToWire(string $value): string
    {
        $wire = '';
        $ips  = explode(',', $value);

        foreach ($ips as $ip) {
            $packed = inet_pton(trim($ip));

            if ($packed !== false && strlen($packed) === 4) {
                $wire .= $packed;
            }
        }

        return $wire;
    }

    private function ipv6HintToWire(string $value): string
    {
        $wire = '';
        $ips  = explode(',', $value);

        foreach ($ips as $ip) {
            $packed = inet_pton(trim($ip));

            if ($packed !== false && strlen($packed) === 16) {
                $wire .= $packed;
            }
        }

        return $wire;
    }

    private function uriToWire(string $data): ?string
    {
        if (!preg_match('/^(\d+)\s+(\d+)\s+"([^"]*)"$/', $data, $matches)) {
            return null;
        }

        $priority = (int)$matches[1];
        $weight   = (int)$matches[2];
        $target   = $matches[3];

        return pack('nn', $priority, $weight) . $target;
    }
}
