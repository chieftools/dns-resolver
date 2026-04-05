<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Dnssec\WireFormatConverter;

beforeEach(function () {
    $this->converter = new WireFormatConverter;
});

describe('nameToWire', function () {
    it('converts root domain', function () {
        expect($this->converter->nameToWire('.'))->toBe("\x00");
        expect($this->converter->nameToWire(''))->toBe("\x00");
    });

    it('converts simple domain', function () {
        $expected = "\x07example\x03com\x00";
        expect($this->converter->nameToWire('example.com'))->toBe($expected);
        expect($this->converter->nameToWire('example.com.'))->toBe($expected);
    });

    it('lowercases domain', function () {
        expect($this->converter->nameToWire('Example.COM'))->toBe("\x07example\x03com\x00");
    });

    it('handles octal escape sequences', function () {
        // \040 = decimal 32 = space character
        $wire = $this->converter->nameToWire('test\\040label.com');
        expect($wire)->toBe("\x0atest label\x03com\x00");
    });
});

describe('getTypeCode', function () {
    it('returns correct codes for standard types', function () {
        expect($this->converter->getTypeCode('A'))->toBe(1);
        expect($this->converter->getTypeCode('AAAA'))->toBe(28);
        expect($this->converter->getTypeCode('NS'))->toBe(2);
        expect($this->converter->getTypeCode('MX'))->toBe(15);
        expect($this->converter->getTypeCode('TXT'))->toBe(16);
        expect($this->converter->getTypeCode('DNSKEY'))->toBe(48);
        expect($this->converter->getTypeCode('HTTPS'))->toBe(65);
    });

    it('handles TYPEnn format', function () {
        expect($this->converter->getTypeCode('TYPE64'))->toBe(64);
        expect($this->converter->getTypeCode('TYPE65'))->toBe(65);
    });

    it('is case-insensitive', function () {
        expect($this->converter->getTypeCode('a'))->toBe(1);
        expect($this->converter->getTypeCode('aaaa'))->toBe(28);
    });

    it('returns null for unknown types', function () {
        expect($this->converter->getTypeCode('UNKNOWN'))->toBeNull();
    });
});

describe('rdataToWire', function () {
    it('converts A record', function () {
        $wire = $this->converter->rdataToWire('A', '192.0.2.1');
        expect($wire)->toBe(inet_pton('192.0.2.1'));
    });

    it('converts AAAA record', function () {
        $wire = $this->converter->rdataToWire('AAAA', '2001:db8::1');
        expect($wire)->toBe(inet_pton('2001:db8::1'));
    });

    it('converts NS record', function () {
        $wire = $this->converter->rdataToWire('NS', 'ns1.example.com.');
        expect($wire)->toBe("\x03ns1\x07example\x03com\x00");
    });

    it('converts CNAME record', function () {
        $wire = $this->converter->rdataToWire('CNAME', 'www.example.com.');
        expect($wire)->toBe("\x03www\x07example\x03com\x00");
    });

    it('converts MX record', function () {
        $wire = $this->converter->rdataToWire('MX', '10 mail.example.com.');
        expect($wire)->toBe(pack('n', 10) . "\x04mail\x07example\x03com\x00");
    });

    it('converts TXT record', function () {
        $wire     = $this->converter->rdataToWire('TXT', 'v=spf1 include:_spf.google.com ~all');
        $expected = chr(35) . 'v=spf1 include:_spf.google.com ~all';
        expect($wire)->toBe($expected);
    });

    it('converts multi-string TXT record', function () {
        $wire = $this->converter->rdataToWire('TXT', 'part one" "part two');
        expect($wire)->toBe(chr(8) . 'part one' . chr(8) . 'part two');
    });

    it('converts SOA record', function () {
        $wire = $this->converter->rdataToWire('SOA', 'ns1.example.com. admin.example.com. 2024010100 3600 900 604800 86400');
        expect($wire)->not->toBeNull();
        expect(str_starts_with($wire, "\x03ns1\x07example\x03com\x00"))->toBeTrue();
    });

    it('converts SRV record', function () {
        $wire = $this->converter->rdataToWire('SRV', '10 20 443 target.example.com.');
        expect($wire)->toBe(pack('nnn', 10, 20, 443) . "\x06target\x07example\x03com\x00");
    });

    it('converts CAA record', function () {
        $wire = $this->converter->rdataToWire('CAA', '0 issue "letsencrypt.org"');
        expect($wire)->toBe(pack('CC', 0, 5) . 'issueletsencrypt.org');
    });

    it('converts DS record', function () {
        $wire = $this->converter->rdataToWire('DS', '12345 8 2 AABBCCDD');
        expect($wire)->toBe(pack('nCC', 12345, 8, 2) . hex2bin('AABBCCDD'));
    });

    it('converts DNSKEY record', function () {
        $key  = base64_encode('testkey');
        $wire = $this->converter->rdataToWire('DNSKEY', "257 3 13 {$key}");
        expect($wire)->toBe(pack('nCC', 257, 3, 13) . 'testkey');
    });

    it('converts SSHFP record', function () {
        $wire = $this->converter->rdataToWire('SSHFP', '2 1 AABBCCDD');
        expect($wire)->toBe(pack('CC', 2, 1) . hex2bin('AABBCCDD'));
    });

    it('converts TLSA record', function () {
        $wire = $this->converter->rdataToWire('TLSA', '3 1 1 AABBCCDD');
        expect($wire)->toBe(pack('CCC', 3, 1, 1) . hex2bin('AABBCCDD'));
    });

    it('converts HTTPS/SVCB record', function () {
        $wire = $this->converter->rdataToWire('HTTPS', '1 . alpn=h2,h3');
        expect($wire)->not->toBeNull();
        // priority=1, target=root, then alpn params
        expect(str_starts_with($wire, pack('n', 1) . "\x00"))->toBeTrue();
    });

    it('converts URI record', function () {
        $wire = $this->converter->rdataToWire('URI', '10 1 "ftp://example.com"');
        expect($wire)->toBe(pack('nn', 10, 1) . 'ftp://example.com');
    });

    it('returns null for unknown types', function () {
        expect($this->converter->rdataToWire('UNKNOWN', 'data'))->toBeNull();
    });
});

describe('buildTypeBitmap', function () {
    it('builds bitmap for common types', function () {
        $bitmap = $this->converter->buildTypeBitmap(['A', 'NS', 'MX']);
        expect($bitmap)->not->toBeEmpty();
        // All are in window 0, so first byte is 0
        expect(ord($bitmap[0]))->toBe(0);
    });

    it('handles types in different windows', function () {
        // CAA is type 257 = window 1, offset 1
        $bitmap = $this->converter->buildTypeBitmap(['A', 'CAA']);
        expect(strlen($bitmap))->toBeGreaterThan(3);
    });
});

describe('base32Decode', function () {
    it('decodes valid base32hex', function () {
        // Known encoding: "test" = base32hex
        $decoded = $this->converter->base32Decode('EHIN6T0');
        expect($decoded)->not->toBeNull();
    });

    it('returns null for invalid characters', function () {
        expect($this->converter->base32Decode('!!!INVALID'))->toBeNull();
    });
});
