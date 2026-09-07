<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use function implode;
use function is_readable;
use function mb_strlen;
use function mb_substr;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Structure;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use UnexpectedValueException;

/**
 * verify() used to re-encode the signed part from the parsed object, so the signature was checked over what the
 * parser produced rather than over what the signer signed. Every encoding the parser normalised away gave another
 * byte string that verified just as well, and fromDER() let trailing bytes through on top of that. One certificate
 * therefore had an unlimited supply of distinct digests, which defeats pinning, deny-listing or deduplicating by
 * the digest of what was received.
 *
 * @internal
 */
final class SignedStructureMalleabilityTest extends TestCase
{
    #[Test]
    public function certificateTrailingDataIsRejected(): void
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('bytes were given');
        Certificate::fromDER(self::leafDER() . 'ATTACKER-CONTROLLED-TRAILING-DATA');
    }

    #[Test]
    public function certificationRequestTrailingDataIsRejected(): void
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('bytes were given');
        CertificationRequest::fromDER(self::csrDER() . 'ATTACKER-CONTROLLED-TRAILING-DATA');
    }

    #[Test]
    public function attributeCertificateTrailingDataIsRejected(): void
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('bytes were given');
        AttributeCertificate::fromDER(self::acDER() . 'ATTACKER-CONTROLLED-TRAILING-DATA');
    }

    #[Test]
    public function aNonMinimalSerialNumberNoLongerVerifies(): void
    {
        $der = self::leafDER();
        $issuerKey = self::issuerPublicKey();
        static::assertTrue(Certificate::fromDER($der)->verify($issuerKey), 'The untouched certificate must verify.');

        // The serial number, re-encoded with a redundant leading zero octet: same value, different bytes.
        $mutated = self::withPaddedInteger($der, 1);
        static::assertNotSame($der, $mutated);

        $cert = Certificate::fromDER($mutated);
        // The mutated encoding still parses to the very same certificate ...
        static::assertSame(
            Certificate::fromDER($der)->tbsCertificate()
                ->serialNumber(),
            $cert->tbsCertificate()
                ->serialNumber()
        );
        // ... but it is no longer the byte string the issuer signed.
        static::assertFalse($cert->verify($issuerKey));
    }

    #[Test]
    public function aNonMinimalCertificationRequestVersionNoLongerVerifies(): void
    {
        $der = self::csrDER();
        static::assertTrue(CertificationRequest::fromDER($der)->verify(), 'The untouched request must verify.');

        $csr = CertificationRequest::fromDER(self::withPaddedInteger($der, 0));
        static::assertSame(0, $csr->certificationRequestInfo()->version());
        static::assertFalse($csr->verify());
    }

    #[Test]
    public function aNonMinimalAttributeCertificateVersionNoLongerVerifies(): void
    {
        $der = self::acDER();
        $issuerKey = self::acIssuerPublicKey();
        static::assertTrue(
            AttributeCertificate::fromDER($der)->verify($issuerKey),
            'The untouched attribute certificate must verify.'
        );

        $ac = AttributeCertificate::fromDER(self::withPaddedInteger($der, 0));
        static::assertSame(1, $ac->acinfo()->version());
        static::assertFalse($ac->verify($issuerKey));
    }

    #[Test]
    public function anIndefiniteLengthEncodingIsRejected(): void
    {
        // BER, not DER: the signed bytes cannot be isolated, and re-encoding them would bring the malleability back.
        $parts = Structure::explodeDER(self::leafDER());
        $ber = "\x30\x80" . implode('', $parts) . "\x00\x00";

        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Certificate must be DER encoded.');
        Certificate::fromDER($ber);
    }

    #[Test]
    public function theSignatureAlgorithmMustRepeatTheSignedOne(): void
    {
        // signatureAlgorithm sits outside the tbsCertificate, so anyone can change it. RFC 5280 section 4.1.1.2
        // requires it to repeat the algorithm of the signed part.
        $seq = Certificate::fromDER(self::leafDER())->toASN1();
        $seq = $seq->withReplaced(1, SHA512WithRSAEncryptionAlgorithmIdentifier::create()->toASN1());

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('does not match the algorithm');
        Certificate::fromASN1($seq);
    }

    #[Test]
    public function realCertificatesStillVerify(): void
    {
        $store = '/etc/ssl/certs/ca-certificates.crt';
        if (! is_readable($store)) {
            static::markTestSkipped('No system trust store available.');
        }
        $checked = 0;
        foreach (PEMBundle::fromFile($store) as $pem) {
            $cert = Certificate::fromDER($pem->data());
            // Self-signed roots verify under their own key, which exercises the retained bytes end to end.
            if (! $cert->isSelfIssued()) {
                continue;
            }
            static::assertTrue(
                $cert->verify($cert->tbsCertificate()->subjectPublicKeyInfo()),
                (string) $cert->tbsCertificate()
                    ->subject()
            );
            if (++$checked === 20) {
                break;
            }
        }
        static::assertGreaterThan(0, $checked);
    }

    #[Test]
    public function structuresBuiltInMemoryStillVerify(): void
    {
        // Nothing was ever received as bytes here, so verify() falls back to re-encoding, which is correct for a
        // structure built in memory.
        $cert = Certificate::fromDER(self::leafDER());
        static::assertTrue(Certificate::fromASN1($cert->toASN1())->verify(self::issuerPublicKey()));
        static::assertTrue(CertificationRequest::fromASN1(CertificationRequest::fromDER(self::csrDER())->toASN1())->verify());
    }

    private static function leafDER(): string
    {
        return PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem')->data();
    }

    private static function csrDER(): string
    {
        return PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.csr')->data();
    }

    private static function acDER(): string
    {
        return PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem')->data();
    }

    private static function issuerPublicKey(): PublicKeyInfo
    {
        return Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'))->tbsCertificate()
            ->subjectPublicKeyInfo();
    }

    private static function acIssuerPublicKey(): PublicKeyInfo
    {
        return PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey()
            ->publicKeyInfo();
    }

    /**
     * Re-encode the INTEGER at the given index of the signed part with a redundant leading zero octet, and rebuild
     * the enclosing sequences around it. The value is unchanged, so the structure parses just the same; only the
     * bytes differ.
     */
    private static function withPaddedInteger(string $der, int $index): string
    {
        $parts = Structure::explodeDER($der);
        $signed = Structure::explodeDER($parts[0]);
        $signed[$index] = self::withLeadingZero($signed[$index]);
        $parts[0] = self::sequence(...$signed);
        return self::sequence(...$parts);
    }

    private static function withLeadingZero(string $der): string
    {
        $offset = 0;
        Identifier::fromDER($der, $offset);
        $length = Length::expectFromDER($der, $offset)->intLength();
        $content = "\x00" . mb_substr($der, $offset, $length, '8bit');
        return mb_substr($der, 0, 1, '8bit') . Length::create(mb_strlen($content, '8bit'))->toDER() . $content;
    }

    private static function sequence(string ...$parts): string
    {
        $content = implode('', $parts);
        return "\x30" . Length::create(mb_strlen($content, '8bit'))->toDER() . $content;
    }
}
