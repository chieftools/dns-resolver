<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Dnssec\Asn1Builder;

beforeEach(function () {
    $this->builder = new Asn1Builder;
});

describe('buildInteger', function () {
    it('encodes small positive integer', function () {
        $result = $this->builder->buildInteger("\x05");
        expect($result)->toBe("\x02\x01\x05");
    });

    it('adds leading zero when high bit set', function () {
        $result = $this->builder->buildInteger("\x80");
        expect($result)->toBe("\x02\x02\x00\x80");
    });

    it('strips unnecessary leading zeros', function () {
        $result = $this->builder->buildInteger("\x00\x00\x42");
        expect($result)->toBe("\x02\x01\x42");
    });

    it('keeps leading zero when next byte has high bit', function () {
        $result = $this->builder->buildInteger("\x00\x80");
        expect($result)->toBe("\x02\x02\x00\x80");
    });
});

describe('buildSequence', function () {
    it('wraps content in SEQUENCE tag', function () {
        $result = $this->builder->buildSequence("\x02\x01\x05");
        expect($result)->toBe("\x30\x03\x02\x01\x05");
    });
});

describe('buildBitString', function () {
    it('wraps content in BIT STRING with unused bits flag', function () {
        $result = $this->builder->buildBitString("\x04\x05");
        expect($result)->toBe("\x03\x03\x00\x04\x05");
    });
});

describe('buildLength', function () {
    it('uses short form for length < 128', function () {
        expect($this->builder->buildLength(5))->toBe("\x05");
        expect($this->builder->buildLength(127))->toBe("\x7F");
    });

    it('uses long form for length 128-255', function () {
        expect($this->builder->buildLength(128))->toBe("\x81\x80");
        expect($this->builder->buildLength(255))->toBe("\x81\xFF");
    });

    it('uses two-byte long form for length 256-65535', function () {
        $result = $this->builder->buildLength(256);
        expect($result)->toBe("\x82\x01\x00");

        $result = $this->builder->buildLength(1024);
        expect($result)->toBe("\x82\x04\x00");
    });
});

describe('rsaDnskeyToPem', function () {
    it('converts valid RSA DNSKEY to PEM', function () {
        // Build a minimal RSA key: expLen=3, exp=65537, modulus=128 bytes
        $exponent = "\x01\x00\x01"; // 65537
        $modulus  = str_repeat("\xAB", 128);
        $key      = chr(3) . $exponent . $modulus;

        $pem = $this->builder->rsaDnskeyToPem($key);

        expect($pem)->not->toBeNull();
        expect($pem)->toContain('-----BEGIN PUBLIC KEY-----');
        expect($pem)->toContain('-----END PUBLIC KEY-----');
    });

    it('handles 3-byte exponent length format', function () {
        $exponent = str_repeat("\x01", 300);
        $modulus  = str_repeat("\xAB", 128);
        $key      = "\x00" . pack('n', 300) . $exponent . $modulus;

        $pem = $this->builder->rsaDnskeyToPem($key);

        expect($pem)->not->toBeNull();
    });

    it('returns null for too-short key', function () {
        expect($this->builder->rsaDnskeyToPem("\x01\x02"))->toBeNull();
    });

    it('returns null for empty modulus', function () {
        // expLen=1, exp=3, no modulus
        expect($this->builder->rsaDnskeyToPem("\x01\x03"))->toBeNull();
    });
});

describe('ecdsaDnskeyToPem', function () {
    it('converts P-256 key to PEM', function () {
        $key = str_repeat("\xAB", 64); // 32 bytes x + 32 bytes y

        $pem = $this->builder->ecdsaDnskeyToPem($key, 'P-256');

        expect($pem)->not->toBeNull();
        expect($pem)->toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('converts P-384 key to PEM', function () {
        $key = str_repeat("\xAB", 96); // 48 bytes x + 48 bytes y

        $pem = $this->builder->ecdsaDnskeyToPem($key, 'P-384');

        expect($pem)->not->toBeNull();
    });

    it('returns null for wrong key length', function () {
        expect($this->builder->ecdsaDnskeyToPem(str_repeat("\xAB", 32), 'P-256'))->toBeNull();
    });

    it('returns null for unsupported curve', function () {
        expect($this->builder->ecdsaDnskeyToPem(str_repeat("\xAB", 64), 'P-521'))->toBeNull();
    });
});

describe('ecdsaRawToDer', function () {
    it('converts P-256 raw signature to DER', function () {
        $sig = str_repeat("\x01", 32) . str_repeat("\x02", 32);

        $der = $this->builder->ecdsaRawToDer($sig, 'P-256');

        expect($der)->not->toBeNull();
        // DER signature starts with SEQUENCE tag
        expect($der[0])->toBe("\x30");
    });

    it('converts P-384 raw signature to DER', function () {
        $sig = str_repeat("\x01", 48) . str_repeat("\x02", 48);

        $der = $this->builder->ecdsaRawToDer($sig, 'P-384');

        expect($der)->not->toBeNull();
    });

    it('returns null for wrong signature length', function () {
        expect($this->builder->ecdsaRawToDer(str_repeat("\x01", 30), 'P-256'))->toBeNull();
    });

    it('returns null for unsupported curve', function () {
        expect($this->builder->ecdsaRawToDer(str_repeat("\x01", 64), 'P-521'))->toBeNull();
    });
});
