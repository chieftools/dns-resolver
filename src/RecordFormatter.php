<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver;

use ChiefTools\DNS\Resolver\Results\Record;
use ChiefTools\DNS\Resolver\Enums\RecordType;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Enums\RecordValidation;

final class RecordFormatter
{
    public static function fromRaw(
        RawRecord $rawRecord,
        RecordValidation $validation = RecordValidation::UNKNOWN,
        ?int $sourceId = null,
    ): ?Record {
        $type = RecordType::tryFrom($rawRecord->type);

        if ($type === null) {
            return null;
        }

        return new Record(
            name: $rawRecord->name,
            type: $type,
            ttl: $rawRecord->ttl,
            data: self::formatData($rawRecord->type, $rawRecord->data),
            rawData: $rawRecord->data,
            validation: $validation,
            sourceId: $sourceId,
        );
    }

    private static function formatData(string $type, string $data): string
    {
        return match ($type) {
            'TXT'            => '"' . str_replace('" "', '', $data) . '"',
            'AAAA'           => self::shortenIPv6($data),
            'TLSA', 'SMIMEA' => self::normalizeHexRecord($data, 3),
            'SSHFP'          => self::normalizeHexRecord($data, 2),
            'DS', 'CDS'      => self::normalizeHexRecord($data, 3),
            default          => $data,
        };
    }

    private static function shortenIPv6(string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return $ip;
        }

        return inet_ntop($packed) ?: $ip;
    }

    private static function normalizeHexRecord(string $data, int $prefixParts): string
    {
        $parts = preg_split('/\s+/', $data, $prefixParts + 1);

        if ($parts === false || count($parts) <= $prefixParts) {
            return $data;
        }

        $prefix  = implode(' ', array_slice($parts, 0, $prefixParts));
        $hexData = preg_replace('/\s+/', '', $parts[$prefixParts]);

        return $prefix . ' ' . $hexData;
    }
}
