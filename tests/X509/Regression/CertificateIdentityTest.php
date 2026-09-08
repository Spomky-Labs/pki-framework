<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * Certificate::equals() compared the serial number, the SHA-1 based key identifier of the subjectPublicKeyInfo
 * and the subject DN, and nothing else.
 *
 * Those are three public values an attacker is free to repeat. CertificateBundle::contains() is built on it, and
 * the API shape invites "is this certificate in my trust store or my pinned set?".
 *
 * @internal
 */
final class CertificateIdentityTest extends TestCase
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
    public function aCertificateAgreeingOnTheThreePublicValuesIsNotTheSameCertificate(): void
    {
        [$root, $rogue] = self::twinCertificates();

        static::assertSame($root->tbsCertificate()->serialNumber(), $rogue->tbsCertificate()->serialNumber());
        static::assertTrue($root->tbsCertificate()->subject()->equals($rogue->tbsCertificate()->subject()));
        static::assertNotSame($root->toDER(), $rogue->toDER());

        static::assertFalse($root->equals($rogue));
        static::assertFalse($rogue->equals($root));
    }

    #[Test]
    public function aTrustStoreDoesNotContainACertificateThatIsNotInIt(): void
    {
        [$root, $rogue] = self::twinCertificates();
        $trustStore = CertificateBundle::create($root);

        static::assertTrue($trustStore->contains($root));
        static::assertFalse($trustStore->contains($rogue));
    }

    #[Test]
    public function aCertificateStillEqualsItself(): void
    {
        [$root] = self::twinCertificates();

        static::assertTrue($root->equals($root));
        static::assertTrue($root->equals(Certificate::fromDER($root->toDER())));
    }

    #[Test]
    public function theLooserPredicateIsAvailableUnderItsOwnName(): void
    {
        [$root, $rogue] = self::twinCertificates();

        static::assertTrue($root->hasEqualSubjectIdentity($rogue));
    }

    /**
     * A real root and a certificate repeating its serial number, subject DN and key, differing in issuer,
     * validity and every extension.
     *
     * @return array{Certificate, Certificate}
     */
    private static function twinCertificates(): array
    {
        $subject = Name::fromString('cn=Corp Root CA');

        $root = TBSCertificate::create(
            $subject,
            self::$key->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 10 years')
        )
            ->withSerialNumber('42')
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true))
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key);

        $rogue = TBSCertificate::create(
            $subject,
            self::$key->publicKeyInfo(),
            Name::fromString('cn=Somewhere Else'),
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        )
            ->withSerialNumber('42')
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key);

        return [$root, $rogue];
    }
}
