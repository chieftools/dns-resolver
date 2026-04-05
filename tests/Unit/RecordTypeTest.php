<?php

declare(strict_types=1);

use ChiefTools\DNS\Resolver\Enums\RecordType;

describe('RecordType', function () {
    it('has all expected cases', function () {
        $cases = RecordType::cases();

        expect(count($cases))->toBeGreaterThanOrEqual(27);

        // Check some key types exist
        expect(RecordType::A->value)->toBe('A');
        expect(RecordType::AAAA->value)->toBe('AAAA');
        expect(RecordType::CNAME->value)->toBe('CNAME');
        expect(RecordType::MX->value)->toBe('MX');
        expect(RecordType::TXT->value)->toBe('TXT');
        expect(RecordType::NS->value)->toBe('NS');
        expect(RecordType::SOA->value)->toBe('SOA');
        expect(RecordType::DNSKEY->value)->toBe('DNSKEY');
        expect(RecordType::DS->value)->toBe('DS');
        expect(RecordType::HTTPS->value)->toBe('HTTPS');
    });

    it('can be created from string', function () {
        expect(RecordType::from('A'))->toBe(RecordType::A);
        expect(RecordType::from('AAAA'))->toBe(RecordType::AAAA);
    });

    it('tryFrom returns null for invalid types', function () {
        expect(RecordType::tryFrom('INVALID'))->toBeNull();
    });
});
