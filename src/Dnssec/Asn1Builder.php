<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Dnssec;

/**
 * ASN.1 DER encoding utilities for DNSSEC cryptographic operations.
 *
 * Used to build DER-encoded structures for RSA and ECDSA public keys
 * and signatures that OpenSSL can process.
 */
readonly class Asn1Builder
{
    /**
     * Build an ASN.1 INTEGER.
     *
     * Handles leading zero byte requirements for positive integers.
     */
    public function buildInteger(string $value): string
    {
        // Remove leading zero bytes (but keep one if value would be negative)
        while (strlen($value) > 1 && $value[0] === "\x00" && (ord($value[1]) & 0x80) === 0) {
            $value = substr($value, 1);
        }

        // Add leading zero if high bit is set (to keep it positive)
        if (strlen($value) > 0 && (ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return "\x02" . $this->buildLength(strlen($value)) . $value;
    }

    /**
     * Build an ASN.1 SEQUENCE.
     */
    public function buildSequence(string $content): string
    {
        return "\x30" . $this->buildLength(strlen($content)) . $content;
    }

    /**
     * Build an ASN.1 BIT STRING.
     */
    public function buildBitString(string $content): string
    {
        return "\x03" . $this->buildLength(strlen($content) + 1) . "\x00" . $content;
    }

    /**
     * Build ASN.1 length encoding.
     */
    /**
     * @param int<0, max> $length
     */
    public function buildLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        if ($length < 256) {
            return "\x81" . chr($length);
        }

        if ($length < 65536) {
            return "\x82" . pack('n', $length);
        }

        return "\x83" . pack('Cn', ($length >> 16) & 0xFF, $length & 0xFFFF);
    }

    /**
     * Convert RSA DNSKEY public key to PEM format.
     *
     * DNSKEY RSA format: exponent_length (1 or 3 bytes) + exponent + modulus
     */
    public function rsaDnskeyToPem(string $publicKey): ?string
    {
        $offset = 0;
        $len    = strlen($publicKey);

        if ($len < 3) {
            return null;
        }

        $expLen = ord($publicKey[0]);
        $offset = 1;

        if ($expLen === 0) {
            if ($len < 4) {
                return null;
            }
            $expLen = (ord($publicKey[1]) << 8) | ord($publicKey[2]);
            $offset = 3;
        }

        if ($offset + $expLen > $len) {
            return null;
        }

        $exponent = substr($publicKey, $offset, $expLen);
        $modulus  = substr($publicKey, $offset + $expLen);

        if (strlen($modulus) === 0) {
            return null;
        }

        $modInt    = $this->buildInteger($modulus);
        $expInt    = $this->buildInteger($exponent);
        $pubKeySeq = $this->buildSequence($modInt . $expInt);

        // RSA OID: 1.2.840.113549.1.1.1
        $rsaOid  = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $algoSeq = $this->buildSequence($rsaOid);

        $bitString = $this->buildBitString($pubKeySeq);

        $derKey = $this->buildSequence($algoSeq . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($derKey), 64) . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Convert ECDSA DNSKEY public key to PEM format.
     *
     * DNSKEY ECDSA format: raw x||y coordinates
     */
    public function ecdsaDnskeyToPem(string $publicKey, string $curve): ?string
    {
        $componentLen = match ($curve) {
            'P-256' => 32,
            'P-384' => 48,
            default => null,
        };

        if ($componentLen === null || strlen($publicKey) !== $componentLen * 2) {
            return null;
        }

        $ecPoint = "\x04" . $publicKey;

        $ecOid    = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $curveOid = match ($curve) {
            'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
            'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
            default => null,
        };

        if ($curveOid === null) {
            return null;
        }

        $algoSeq   = $this->buildSequence($ecOid . $curveOid);
        $bitString = $this->buildBitString($ecPoint);
        $derKey    = $this->buildSequence($algoSeq . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($derKey), 64) . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Convert ECDSA raw signature (r||s) to DER format.
     */
    public function ecdsaRawToDer(string $signature, string $curve): ?string
    {
        $componentLen = match ($curve) {
            'P-256' => 32,
            'P-384' => 48,
            default => null,
        };

        if ($componentLen === null || strlen($signature) !== $componentLen * 2) {
            return null;
        }

        $r = substr($signature, 0, $componentLen);
        $s = substr($signature, $componentLen);

        $rInt = $this->buildInteger($r);
        $sInt = $this->buildInteger($s);

        return $this->buildSequence($rInt . $sInt);
    }
}
