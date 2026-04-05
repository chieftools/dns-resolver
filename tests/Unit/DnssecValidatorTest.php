<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Enums\DnssecStatus;
use ChiefTools\DNS\Resolver\Dnssec\DnssecValidator;

beforeEach(function () {
    $this->validator = new DnssecValidator;
});

describe('parseDnskey', function () {
    it('parses valid DNSKEY record', function () {
        $data   = '257 3 13 tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huoanY/2hbxmt5GjEcV';
        $result = $this->validator->parseDnskey($data, 'example.com.');

        expect($result)->not->toBeNull();
        expect($result['flags'])->toBe(257);
        expect($result['protocol'])->toBe(3);
        expect($result['algorithm'])->toBe(13);
        expect($result['name'])->toBe('example.com');
        expect($result['is_ksk'])->toBeTrue();
        expect($result['keytag'])->toBeInt();
    });

    it('identifies ZSK vs KSK', function () {
        $ksk = $this->validator->parseDnskey('257 3 13 ' . base64_encode(str_repeat('x', 64)), 'example.com.');
        $zsk = $this->validator->parseDnskey('256 3 13 ' . base64_encode(str_repeat('x', 64)), 'example.com.');

        expect($ksk['is_ksk'])->toBeTrue();
        expect($zsk['is_ksk'])->toBeFalse();
    });

    it('returns null for invalid data', function () {
        expect($this->validator->parseDnskey('not valid', 'example.com.'))->toBeNull();
    });

    it('returns null for invalid base64', function () {
        expect($this->validator->parseDnskey('257 3 13 !!!invalid!!!', 'example.com.'))->toBeNull();
    });
});

describe('parseDs', function () {
    it('parses valid DS record', function () {
        $data   = '19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A';
        $result = $this->validator->parseDs($data);

        expect($result)->not->toBeNull();
        expect($result['keytag'])->toBe(19718);
        expect($result['algorithm'])->toBe(13);
        expect($result['digest_type'])->toBe(2);
        expect($result['digest'])->toBe('8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A');
    });

    it('handles spaces in digest', function () {
        $data   = '19718 13 2 8ACBB0CD 28F41250';
        $result = $this->validator->parseDs($data);

        expect($result)->not->toBeNull();
        expect($result['digest'])->toBe('8ACBB0CD28F41250');
    });

    it('returns null for invalid data', function () {
        expect($this->validator->parseDs('invalid'))->toBeNull();
    });
});

describe('parseRrsig', function () {
    it('parses valid RRSIG record', function () {
        $sig    = base64_encode(str_repeat("\x01", 64));
        $data   = "A 13 2 300 20261229172605 20261227152605 34505 cloudflare.com. {$sig}";
        $result = $this->validator->parseRrsig($data);

        expect($result)->not->toBeNull();
        expect($result['type_covered'])->toBe('A');
        expect($result['algorithm'])->toBe(13);
        expect($result['labels'])->toBe(2);
        expect($result['original_ttl'])->toBe(300);
        expect($result['keytag'])->toBe(34505);
        expect($result['signer'])->toBe('cloudflare.com');
    });

    it('returns null for invalid timestamp', function () {
        expect($this->validator->parseRrsig('A 13 2 300 invalid 20261227152605 34505 example.com. abc='))->toBeNull();
    });

    it('returns null for invalid data', function () {
        expect($this->validator->parseRrsig('not valid'))->toBeNull();
    });
});

describe('calculateKeyTag', function () {
    it('calculates consistent key tag', function () {
        $tag1 = $this->validator->calculateKeyTag(257, 3, 13, str_repeat('x', 64));
        $tag2 = $this->validator->calculateKeyTag(257, 3, 13, str_repeat('x', 64));

        expect($tag1)->toBe($tag2);
        expect($tag1)->toBeGreaterThanOrEqual(0);
        expect($tag1)->toBeLessThanOrEqual(65535);
    });

    it('produces different tags for different keys', function () {
        $tag1 = $this->validator->calculateKeyTag(257, 3, 13, str_repeat('a', 64));
        $tag2 = $this->validator->calculateKeyTag(257, 3, 13, str_repeat('b', 64));

        expect($tag1)->not->toBe($tag2);
    });
});

describe('verifyDsMatchesDnskey', function () {
    it('verifies matching DS and DNSKEY', function () {
        // Create a DNSKEY and compute its DS
        $flags     = 257;
        $protocol  = 3;
        $algorithm = 13;
        $publicKey = str_repeat("\xAB", 64);
        $name      = 'example.com';

        $keytag = $this->validator->calculateKeyTag($flags, $protocol, $algorithm, $publicKey);

        // Compute DS (SHA-256)
        $ownerWire   = (new ChiefTools\DNS\Resolver\Dnssec\WireFormatConverter)->nameToWire($name);
        $dnskeyRdata = pack('nCC', $flags, $protocol, $algorithm) . $publicKey;
        $digest      = strtoupper(hash('sha256', $ownerWire . $dnskeyRdata));

        $ds = [
            'keytag'      => $keytag,
            'algorithm'   => $algorithm,
            'digest_type' => 2,
            'digest'      => $digest,
        ];

        $dnskey = [
            'keytag'     => $keytag,
            'algorithm'  => $algorithm,
            'flags'      => $flags,
            'protocol'   => $protocol,
            'public_key' => $publicKey,
        ];

        expect($this->validator->verifyDsMatchesDnskey($ds, $dnskey, $name))->toBeTrue();
    });

    it('rejects mismatched keytag', function () {
        $ds     = ['keytag' => 100, 'algorithm' => 13, 'digest_type' => 2, 'digest' => 'AA'];
        $dnskey = ['keytag' => 200, 'algorithm' => 13, 'flags' => 257, 'protocol' => 3, 'public_key' => 'x'];

        expect($this->validator->verifyDsMatchesDnskey($ds, $dnskey, 'example.com'))->toBeFalse();
    });
});

describe('status management', function () {
    it('starts as indeterminate', function () {
        expect($this->validator->getStatus())->toBe(DnssecStatus::INDETERMINATE);
    });

    it('marks signed', function () {
        $this->validator->markSigned();
        expect($this->validator->getStatus())->toBe(DnssecStatus::SIGNED);
    });

    it('marks unsigned', function () {
        $this->validator->markUnsigned('example.com');
        expect($this->validator->getStatus())->toBe(DnssecStatus::UNSIGNED);
    });

    it('marks invalid', function () {
        $this->validator->markInvalid('test error');
        expect($this->validator->getStatus())->toBe(DnssecStatus::INVALID);
        expect($this->validator->getErrors())->toBe(['test error']);
    });

    it('invalid overrides signed', function () {
        $this->validator->markSigned();
        $this->validator->markInvalid('error');
        expect($this->validator->getStatus())->toBe(DnssecStatus::INVALID);
    });

    it('signed does not override invalid', function () {
        $this->validator->markInvalid('error');
        $this->validator->markSigned();
        expect($this->validator->getStatus())->toBe(DnssecStatus::INVALID);
    });

    it('unsigned does not override invalid', function () {
        $this->validator->markInvalid('error');
        $this->validator->markUnsigned('zone');
        expect($this->validator->getStatus())->toBe(DnssecStatus::INVALID);
    });

    it('resets state', function () {
        $this->validator->markInvalid('error');
        $this->validator->reset();
        expect($this->validator->getStatus())->toBe(DnssecStatus::INDETERMINATE);
        expect($this->validator->getErrors())->toBe([]);
    });
});

describe('record validation tracking', function () {
    it('tracks per-record validation', function () {
        $this->validator->setRecordValidation('example.com.', 'A', '1.2.3.4', true);
        expect($this->validator->getRecordValidation('example.com.', 'A', '1.2.3.4'))->toBeTrue();
    });

    it('returns null for untracked records', function () {
        expect($this->validator->getRecordValidation('unknown.com.', 'A', '1.2.3.4'))->toBeNull();
    });

    it('tracks failed validation', function () {
        $this->validator->setRecordValidation('example.com.', 'A', '1.2.3.4', false);
        expect($this->validator->getRecordValidation('example.com.', 'A', '1.2.3.4'))->toBeFalse();
    });
});

describe('zone tracking', function () {
    it('tracks unsigned zones', function () {
        expect($this->validator->isZoneUnsigned('example.com'))->toBeFalse();
        $this->validator->markUnsigned('example.com');
        expect($this->validator->isZoneUnsigned('example.com'))->toBeTrue();
    });

    it('tracks invalid zones', function () {
        expect($this->validator->isZoneInvalid('example.com'))->toBeFalse();
        $this->validator->markZoneInvalid('example.com', 'test');
        expect($this->validator->isZoneInvalid('example.com'))->toBeTrue();
    });

    it('only records first unsigned message per zone', function () {
        $this->validator->markUnsigned('example.com', 'first reason');
        $this->validator->markUnsigned('example.com', 'second reason');
        expect($this->validator->getErrors())->toBe(['first reason']);
    });
});

describe('DNSKEY caching', function () {
    it('caches and retrieves DNSKEYs', function () {
        $dnskeys = [
            ['keytag' => 12345, 'algorithm' => 13, 'flags' => 257, 'protocol' => 3, 'public_key' => 'key', 'name' => '.', 'public_key_b64' => 'a2V5', 'is_ksk' => true],
        ];

        $this->validator->cacheDnskeys('.', $dnskeys);
        expect($this->validator->getCachedDnskeys('.'))->toBe($dnskeys);
    });

    it('returns null for uncached zones', function () {
        expect($this->validator->getCachedDnskeys('example.com'))->toBeNull();
    });

    it('normalizes zone names', function () {
        $dnskeys = [
            ['keytag' => 12345, 'algorithm' => 13, 'flags' => 257, 'protocol' => 3, 'public_key' => 'key', 'name' => 'example.com', 'public_key_b64' => 'a2V5', 'is_ksk' => true],
        ];

        $this->validator->cacheDnskeys('Example.COM.', $dnskeys);
        expect($this->validator->getCachedDnskeys('example.com'))->toBe($dnskeys);
    });
});
