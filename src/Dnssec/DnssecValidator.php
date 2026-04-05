<?php

declare(strict_types=1);

namespace ChiefTools\DNS\Resolver\Dnssec;

use ChiefTools\DNS\Resolver\Enums\Algorithm;
use ChiefTools\DNS\Resolver\Enums\DnssecStatus;

/**
 * DNSSEC validation support for DNS lookups.
 *
 * Implements DNSSEC validation following RFC 4033-4035.
 */
class DnssecValidator
{
    // DS digest type constants
    public const int DIGEST_SHA1   = 1;
    public const int DIGEST_SHA256 = 2;
    public const int DIGEST_SHA384 = 4;

    private Asn1Builder         $asn1;
    private WireFormatConverter $wireFormat;

    /** @var array<string, list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>> */
    private array $rootTrustAnchors;

    /** @var list<string> Validation errors encountered */
    private array $errors = [];

    /** @var DnssecStatus Current validation status */
    private DnssecStatus $status = DnssecStatus::INDETERMINATE;

    /** @var array<string, list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}>> Cached DNSKEY records by zone */
    private array $dnskeyCache = [];

    /** @var array<string, bool|null> Per-record validation status (key: "name|type|data") */
    private array $recordValidation = [];

    /** @var array<string, true> Zones known to be unsigned */
    private array $unsignedZones = [];

    /** @var array<string, true> Zones with invalid DNSSEC */
    private array $invalidZones = [];

    public function __construct(
        ?WireFormatConverter $wireFormat = null,
        ?Asn1Builder $asn1 = null,
    ) {
        $this->wireFormat = $wireFormat ?? new WireFormatConverter;
        $this->asn1       = $asn1 ?? new Asn1Builder;

        // Root zone trust anchors (IANA)
        // Key tag 20326: Root KSK introduced in 2017, algorithm 8 (RSA-SHA256)
        $this->rootTrustAnchors = [
            '.' => [
                [
                    'keytag'      => 20326,
                    'algorithm'   => Algorithm::RSASHA256->value,
                    'digest_type' => self::DIGEST_SHA256,
                    'digest'      => 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
                ],
            ],
        ];
    }

    /**
     * Reset validation state for a new lookup.
     */
    public function reset(): void
    {
        $this->errors           = [];
        $this->status           = DnssecStatus::INDETERMINATE;
        $this->dnskeyCache      = [];
        $this->recordValidation = [];
        $this->unsignedZones    = [];
        $this->invalidZones     = [];
    }

    public function getStatus(): DnssecStatus
    {
        return $this->status;
    }

    /**
     * @return list<string>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    private function recordKey(string $name, string $type, string $data): string
    {
        return strtolower(rtrim($name, '.')) . '|' . $type . '|' . $data;
    }

    public function setRecordValidation(string $name, string $type, string $data, ?bool $validated): void
    {
        $this->recordValidation[$this->recordKey($name, $type, $data)] = $validated;
    }

    /**
     * @return bool|null true = validated, false = failed, null = not validated
     */
    public function getRecordValidation(string $name, string $type, string $data): ?bool
    {
        return $this->recordValidation[$this->recordKey($name, $type, $data)] ?? null;
    }

    public function markUnsigned(string $zone, ?string $reason = null): void
    {
        $zone = strtolower(rtrim($zone, '.'));

        if (isset($this->unsignedZones[$zone])) {
            return;
        }

        $this->unsignedZones[$zone] = true;

        if ($this->status !== DnssecStatus::INVALID) {
            $this->status = DnssecStatus::UNSIGNED;
        }

        if ($reason !== null) {
            $this->errors[] = $reason;
        }
    }

    public function isZoneUnsigned(string $zone): bool
    {
        $zone = strtolower(rtrim($zone, '.'));

        return isset($this->unsignedZones[$zone]);
    }

    public function markZoneInvalid(string $zone, string $reason): void
    {
        $zone                      = strtolower(rtrim($zone, '.'));
        $this->invalidZones[$zone] = true;
        $this->status              = DnssecStatus::INVALID;
        $this->errors[]            = $reason;
    }

    public function isZoneInvalid(string $zone): bool
    {
        $zone = strtolower(rtrim($zone, '.'));

        return isset($this->invalidZones[$zone]);
    }

    public function markInvalid(string $reason): void
    {
        $this->status   = DnssecStatus::INVALID;
        $this->errors[] = $reason;
    }

    public function markSigned(): void
    {
        if ($this->status === DnssecStatus::INDETERMINATE) {
            $this->status = DnssecStatus::SIGNED;
        }
    }

    /**
     * Parse a DNSKEY record from dig output.
     *
     * @return array{name: string, flags: int, protocol: int, algorithm: int, public_key: string, public_key_b64: string, keytag: int, is_ksk: bool}|null
     */
    public function parseDnskey(string $data, string $name): ?array
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/s', $data, $matches)) {
            return null;
        }

        $flags        = (int)$matches[1];
        $protocol     = (int)$matches[2];
        $algorithm    = (int)$matches[3];
        $publicKeyB64 = preg_replace('/\s+/', '', $matches[4]);

        if ($publicKeyB64 === null) {
            return null;
        }

        $publicKey = base64_decode($publicKeyB64, true);

        if ($publicKey === false) {
            return null;
        }

        $keyTag = $this->calculateKeyTag($flags, $protocol, $algorithm, $publicKey);

        return [
            'name'           => strtolower(rtrim($name, '.')),
            'flags'          => $flags,
            'protocol'       => $protocol,
            'algorithm'      => $algorithm,
            'public_key'     => $publicKey,
            'public_key_b64' => $publicKeyB64,
            'keytag'         => $keyTag,
            'is_ksk'         => ($flags & 0x0001) === 1,
        ];
    }

    /**
     * Parse a DS record from dig output.
     *
     * @return array{keytag: int, algorithm: int, digest_type: int, digest: string}|null
     */
    public function parseDs(string $data): ?array
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f\s]+)$/', $data, $matches)) {
            return null;
        }

        return [
            'keytag'      => (int)$matches[1],
            'algorithm'   => (int)$matches[2],
            'digest_type' => (int)$matches[3],
            'digest'      => strtoupper(preg_replace('/\s+/', '', $matches[4]) ?? ''),
        ];
    }

    /**
     * Parse an RRSIG record from dig output.
     *
     * @return array{type_covered: string, algorithm: int, labels: int, original_ttl: int, expiration: int, inception: int, keytag: int, signer: string, signature: string, signature_b64: string}|null
     */
    public function parseRrsig(string $data): ?array
    {
        $data = preg_replace('/\s+/', ' ', trim($data));

        if ($data === null || !preg_match('/^([A-Z0-9]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d{14})\s+(\d{14})\s+(\d+)\s+(\S+)\s+(.+)$/s', $data, $matches)) {
            return null;
        }

        $expiration = $this->parseRrsigTimestamp($matches[5]);
        $inception  = $this->parseRrsigTimestamp($matches[6]);

        if ($expiration === null || $inception === null) {
            return null;
        }

        $signatureB64 = preg_replace('/\s+/', '', $matches[9]);

        if ($signatureB64 === null) {
            return null;
        }

        $signature = base64_decode($signatureB64, true);

        if ($signature === false) {
            return null;
        }

        return [
            'type_covered'  => $matches[1],
            'algorithm'     => (int)$matches[2],
            'labels'        => (int)$matches[3],
            'original_ttl'  => (int)$matches[4],
            'expiration'    => $expiration,
            'inception'     => $inception,
            'keytag'        => (int)$matches[7],
            'signer'        => strtolower(rtrim($matches[8], '.')),
            'signature'     => $signature,
            'signature_b64' => $signatureB64,
        ];
    }

    private function parseRrsigTimestamp(string $ts): ?int
    {
        $dt = \DateTimeImmutable::createFromFormat('YmdHis', $ts, new \DateTimeZone('UTC'));

        return $dt ? $dt->getTimestamp() : null;
    }

    /**
     * Calculate the key tag for a DNSKEY record (RFC 4034 Appendix B).
     */
    public function calculateKeyTag(int $flags, int $protocol, int $algorithm, string $publicKey): int
    {
        $rdata = pack('nCC', $flags, $protocol, $algorithm) . $publicKey;

        $ac  = 0;
        $len = strlen($rdata);

        for ($i = 0; $i < $len; $i++) {
            $ac += ($i & 1) ? ord($rdata[$i]) : (ord($rdata[$i]) << 8);
        }

        $ac += ($ac >> 16) & 0xFFFF;

        return $ac & 0xFFFF;
    }

    /**
     * Verify a DS record matches a DNSKEY.
     *
     * @param array{keytag: int, algorithm: int, digest_type: int, digest: string}              $ds
     * @param array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string} $dnskey
     */
    public function verifyDsMatchesDnskey(array $ds, array $dnskey, string $ownerName): bool
    {
        if ($ds['keytag'] !== $dnskey['keytag'] || $ds['algorithm'] !== $dnskey['algorithm']) {
            return false;
        }

        $ownerWire   = $this->wireFormat->nameToWire(strtolower(rtrim($ownerName, '.')));
        $dnskeyRdata = pack('nCC', $dnskey['flags'], $dnskey['protocol'], $dnskey['algorithm']) . $dnskey['public_key'];
        $dataToHash  = $ownerWire . $dnskeyRdata;

        $calculatedDigest = match ($ds['digest_type']) {
            self::DIGEST_SHA1   => strtoupper(hash('sha1', $dataToHash)),
            self::DIGEST_SHA256 => strtoupper(hash('sha256', $dataToHash)),
            self::DIGEST_SHA384 => strtoupper(hash('sha384', $dataToHash)),
            default             => null,
        };

        if ($calculatedDigest === null) {
            return false;
        }

        return hash_equals($calculatedDigest, $ds['digest']);
    }

    /**
     * Verify an RRSIG signature over an RRset.
     *
     * @param array{type_covered: string, algorithm: int, labels: int, original_ttl: int, expiration: int, inception: int, keytag: int, signer: string, signature: string} $rrsig
     * @param list<array{name: string, class: string, type: string, ttl: int, data: string}>                                                                               $rrset
     * @param array{keytag: int, algorithm: int, public_key: string}                                                                                                       $dnskey
     */
    public function verifyRrsig(array $rrsig, array $rrset, array $dnskey): bool
    {
        $now = time();

        if ($now < $rrsig['inception']) {
            return false;
        }

        if ($now > $rrsig['expiration']) {
            return false;
        }

        if ($rrsig['keytag'] !== $dnskey['keytag']) {
            return false;
        }

        if ($rrsig['algorithm'] !== $dnskey['algorithm']) {
            return false;
        }

        $signedData = $this->buildRrsigSignedData($rrsig, $rrset);

        if ($signedData === null) {
            return false;
        }

        return $this->verifySignature($signedData, $rrsig['signature'], $dnskey);
    }

    /**
     * @param list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}> $dnskeys
     */
    public function validateRootDnskeys(array $dnskeys): bool
    {
        $anchors = $this->rootTrustAnchors['.'] ?? [];

        foreach ($anchors as $anchor) {
            foreach ($dnskeys as $dnskey) {
                if ($dnskey['keytag'] === $anchor['keytag']
                    && $dnskey['algorithm'] === $anchor['algorithm']
                    && $this->verifyDsMatchesDnskey($anchor, $dnskey, '.')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param list<array{keytag: int, algorithm: int, digest_type: int, digest: string}>                                                                  $dsRecords
     * @param list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}> $dnskeys
     *
     * @return array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}|null
     */
    public function findMatchingDnskey(array $dsRecords, array $dnskeys, string $zone): ?array
    {
        foreach ($dsRecords as $ds) {
            foreach ($dnskeys as $dnskey) {
                if ($this->verifyDsMatchesDnskey($ds, $dnskey, $zone)) {
                    return $dnskey;
                }
            }
        }

        return null;
    }

    /**
     * @param array{keytag: int, algorithm: int}                                                                                                          $rrsig
     * @param list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}> $dnskeys
     *
     * @return array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}|null
     */
    public function findSigningKey(array $rrsig, array $dnskeys): ?array
    {
        foreach ($dnskeys as $dnskey) {
            if ($dnskey['keytag'] === $rrsig['keytag'] && $dnskey['algorithm'] === $rrsig['algorithm']) {
                return $dnskey;
            }
        }

        return null;
    }

    /**
     * @param list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}> $dnskeys
     */
    public function cacheDnskeys(string $zone, array $dnskeys): void
    {
        $zone                     = strtolower(rtrim($zone, '.'));
        $this->dnskeyCache[$zone] = $dnskeys;
    }

    /**
     * @return list<array{keytag: int, algorithm: int, flags: int, protocol: int, public_key: string, name: string, public_key_b64: string, is_ksk: bool}>|null
     */
    public function getCachedDnskeys(string $zone): ?array
    {
        $zone = strtolower(rtrim($zone, '.'));

        return $this->dnskeyCache[$zone] ?? null;
    }

    /**
     * Build the data that is signed by an RRSIG.
     *
     * @param array{type_covered: string, algorithm: int, labels: int, original_ttl: int, expiration: int, inception: int, keytag: int, signer: string} $rrsig
     * @param list<array{name: string, class: string, type: string, ttl: int, data: string}>                                                            $rrset
     */
    private function buildRrsigSignedData(array $rrsig, array $rrset): ?string
    {
        $typeCode = $this->wireFormat->getTypeCode($rrsig['type_covered']);

        if ($typeCode === null) {
            return null;
        }

        $signerWire = $this->wireFormat->nameToWire($rrsig['signer']);

        $rrsigRdata = pack('nCCNNNn',
            $typeCode,
            $rrsig['algorithm'],
            $rrsig['labels'],
            $rrsig['original_ttl'],
            $rrsig['expiration'],
            $rrsig['inception'],
            $rrsig['keytag'],
        ) . $signerWire;

        $canonicalRrset = $this->buildCanonicalRrset($rrset, $rrsig);

        if ($canonicalRrset === null) {
            return null;
        }

        return $rrsigRdata . $canonicalRrset;
    }

    /**
     * Build the canonical wire format of an RRset for signature verification.
     *
     * @param list<array{name: string, class: string, type: string, ttl: int, data: string}> $rrset
     * @param array{labels: int, original_ttl: int}                                          $rrsig
     */
    private function buildCanonicalRrset(array $rrset, array $rrsig): ?string
    {
        $rrData = [];

        foreach ($rrset as $rr) {
            if ($rr['type'] === 'RRSIG') {
                continue;
            }

            $ownerName  = strtolower(rtrim($rr['name'], '.'));
            $labels     = explode('.', $ownerName);
            $labelCount = count($labels);

            if ($rrsig['labels'] < $labelCount) {
                $ownerName = '*.' . implode('.', array_slice($labels, $labelCount - $rrsig['labels']));
            }

            $nameWire = $this->wireFormat->nameToWire($ownerName);

            $typeCode  = $this->wireFormat->getTypeCode($rr['type']);
            $classCode = 1; // IN class

            if ($typeCode === null) {
                continue;
            }

            $rdataWire = $this->wireFormat->rdataToWire($rr['type'], $rr['data']);

            if ($rdataWire === null) {
                continue;
            }

            $rrWire = $nameWire
                      . pack('nnNn', $typeCode, $classCode, $rrsig['original_ttl'], strlen($rdataWire))
                      . $rdataWire;

            $rrData[] = ['wire' => $rrWire, 'rdata' => $rdataWire];
        }

        if (empty($rrData)) {
            return null;
        }

        usort($rrData, static fn (array $a, array $b): int => strcmp($a['rdata'], $b['rdata']));

        return implode('', array_column($rrData, 'wire'));
    }

    /**
     * @param array{algorithm: int, public_key: string} $dnskey
     */
    private function verifySignature(string $data, string $signature, array $dnskey): bool
    {
        return match ($dnskey['algorithm']) {
            Algorithm::RSASHA1->value,
            Algorithm::RSASHA1NSEC3->value    => $this->verifyRsaSignature($data, $signature, $dnskey, 'sha1'),
            Algorithm::RSASHA256->value       => $this->verifyRsaSignature($data, $signature, $dnskey, 'sha256'),
            Algorithm::RSASHA512->value       => $this->verifyRsaSignature($data, $signature, $dnskey, 'sha512'),
            Algorithm::ECDSAP256SHA256->value => $this->verifyEcdsaSignature($data, $signature, $dnskey, 'sha256', 'P-256'),
            Algorithm::ECDSAP384SHA384->value => $this->verifyEcdsaSignature($data, $signature, $dnskey, 'sha384', 'P-384'),
            Algorithm::ED25519->value         => $this->verifyEd25519Signature($data, $signature, $dnskey),
            default                           => false,
        };
    }

    /**
     * @param array{public_key: string} $dnskey
     */
    private function verifyRsaSignature(string $data, string $signature, array $dnskey, string $hashAlgo): bool
    {
        $publicKeyPem = $this->asn1->rsaDnskeyToPem($dnskey['public_key']);

        if ($publicKeyPem === null) {
            return false;
        }

        $pubKey = openssl_pkey_get_public($publicKeyPem);

        if ($pubKey === false) {
            return false;
        }

        $algo = match ($hashAlgo) {
            'sha1'   => OPENSSL_ALGO_SHA1,
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha512' => OPENSSL_ALGO_SHA512,
            default  => OPENSSL_ALGO_SHA256,
        };

        return openssl_verify($data, $signature, $pubKey, $algo) === 1;
    }

    /**
     * @param array{public_key: string} $dnskey
     */
    private function verifyEcdsaSignature(string $data, string $signature, array $dnskey, string $hashAlgo, string $curve): bool
    {
        $derSignature = $this->asn1->ecdsaRawToDer($signature, $curve);

        if ($derSignature === null) {
            return false;
        }

        $publicKeyPem = $this->asn1->ecdsaDnskeyToPem($dnskey['public_key'], $curve);

        if ($publicKeyPem === null) {
            return false;
        }

        $pubKey = openssl_pkey_get_public($publicKeyPem);

        if ($pubKey === false) {
            return false;
        }

        $algo = match ($hashAlgo) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            default  => OPENSSL_ALGO_SHA256,
        };

        return openssl_verify($data, $derSignature, $pubKey, $algo) === 1;
    }

    /**
     * @param array{public_key: string} $dnskey
     */
    private function verifyEd25519Signature(string $data, string $signature, array $dnskey): bool
    {
        if (strlen($dnskey['public_key']) !== 32) {
            return false;
        }

        // Ed25519 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { key } }
        $derPrefix    = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";
        $publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
                        . chunk_split(base64_encode($derPrefix . $dnskey['public_key']), 64, "\n")
                        . '-----END PUBLIC KEY-----';

        $pubKey = openssl_pkey_get_public($publicKeyPem);

        if ($pubKey === false) {
            return false;
        }

        // Ed25519 does not use a separate hash — pass 0 for the algorithm
        return openssl_verify($data, $signature, $pubKey, 0) === 1;
    }
}
