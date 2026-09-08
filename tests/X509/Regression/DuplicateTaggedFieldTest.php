<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * hasTagged() and getTagged() build a lookup keyed by tag number, so the last element with a given tag wins.
 * TBSCertificate reads its fixed fields by position and its optional ones by tag, so a second [3] block silently
 * replaced the first: a certificate stating basicConstraints CA:FALSE and a critical keyUsage was read as a CA
 * certificate with neither. The whole tbsCertificate is signed, so this matters wherever the attacker controls the
 * signature, and wherever an intake pipeline screens the same bytes with a stricter parser first.
 *
 * OpenSSL and python-cryptography both reject such an encoding outright.
 *
 * @internal
 */
final class DuplicateTaggedFieldTest extends TestCase
{
    private static ?PrivateKeyInfo $key = null;

    public static function setUpBeforeClass(): void
    {
        self::$key = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))
            ->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$key = null;
    }

    #[Test]
    public function aSecondExtensionsBlockIsRejected(): void
    {
        $der = self::signedCertificateWithExtraTBSElement(ExplicitlyTaggedType::create(3, Extensions::create(
            BasicConstraintsExtension::create(true, true, 5)
        )->toASN1()));

        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('TBSCertificate has more than one [3] element.');
        Certificate::fromDER($der);
    }

    #[Test]
    public function aSecondIssuerUniqueIDIsRejected(): void
    {
        $der = self::signedCertificateWithExtraTBSElement(
            ExplicitlyTaggedType::create(1, NullType::create()),
            ExplicitlyTaggedType::create(1, NullType::create())
        );

        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('TBSCertificate has more than one [1] element.');
        Certificate::fromDER($der);
    }

    #[Test]
    public function anUntaggedTrailingElementIsRejected(): void
    {
        $der = self::signedCertificateWithExtraTBSElement(Integer::create(1));

        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('TBSCertificate has an unexpected element');
        Certificate::fromDER($der);
    }

    #[Test]
    public function anUndefinedContextTagIsRejected(): void
    {
        $der = self::signedCertificateWithExtraTBSElement(ExplicitlyTaggedType::create(4, NullType::create()));

        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('TBSCertificate has an unexpected element');
        Certificate::fromDER($der);
    }

    #[Test]
    public function anOrdinaryCertificateStillDecodes(): void
    {
        $certificate = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem'));
        static::assertTrue($certificate->tbsCertificate()->extensions()->hasBasicConstraints());
    }

    /**
     * Build a certificate whose tbsCertificate carries the given extra elements, self-signed over exactly the bytes
     * that are produced, so the signature is genuine and only the structure is at fault.
     */
    private static function signedCertificateWithExtraTBSElement(Element ...$extra): string
    {
        $tbs = TBSCertificate::create(
            Name::fromString('cn=EE'),
            self::$key->publicKeyInfo(),
            Name::fromString('cn=EE'),
            Validity::fromStrings('2024-01-01 12:00:00 UTC', '2034-01-01 12:00:00 UTC')
        )
            ->withSerialNumber(1)
            ->withExtensions(Extensions::create(
                BasicConstraintsExtension::create(true, false),
                KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE)
            ))
            ->withSignature(SHA256WithRSAEncryptionAlgorithmIdentifier::create())
            ->withVersion(TBSCertificate::VERSION_3);

        $elements = [];
        foreach ($tbs->toASN1()->elements() as $element) {
            $elements[] = $element->asElement();
        }
        $forged = Sequence::create(...$elements, ...$extra);
        $signature = Crypto::getDefault()->sign(
            $forged->toDER(),
            self::$key,
            SHA256WithRSAEncryptionAlgorithmIdentifier::create()
        );

        return Sequence::create(
            $forged,
            SHA256WithRSAEncryptionAlgorithmIdentifier::create()->toASN1(),
            $signature->bitString()
        )->toDER();
    }
}
