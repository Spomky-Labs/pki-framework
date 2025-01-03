<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * @internal
 */
final class CertificateVersionTest extends TestCase
{
    private static ?OneAsymmetricKey $_privateKeyInfo = null;

    private static ?TBSCertificate $_tbsCert = null;

    public static function setUpBeforeClass(): void
    {
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $subject = Name::fromString('cn=Test Subject');
        $issuer = Name::fromString('cn=Test Issuer');
        $pki = self::$_privateKeyInfo->publicKeyInfo();
        $validity = Validity::fromStrings('now', 'now + 1 day', 'UTC');
        self::$_tbsCert = TBSCertificate::create($subject, $pki, $issuer, $validity);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privateKeyInfo = null;
        self::$_tbsCert = null;
    }

    #[Test]
    public function version1()
    {
        $cert = self::$_tbsCert->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertSame(TBSCertificate::VERSION_1, $cert->tbsCertificate()->version());
    }

    #[Test]
    public function version2SubjectUID()
    {
        $tbsCert = self::$_tbsCert->withSubjectUniqueID(UniqueIdentifier::fromString('subject'));
        $cert = $tbsCert->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertSame(TBSCertificate::VERSION_2, $cert->tbsCertificate()->version());
    }

    #[Test]
    public function version2IssuerUID()
    {
        $tbsCert = self::$_tbsCert->withIssuerUniqueID(UniqueIdentifier::fromString('issuer'));
        $cert = $tbsCert->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertSame(TBSCertificate::VERSION_2, $cert->tbsCertificate()->version());
    }

    #[Test]
    public function version2BothUID()
    {
        $tbsCert = self::$_tbsCert->withSubjectUniqueID(
            UniqueIdentifier::fromString('subject')
        )->withIssuerUniqueID(UniqueIdentifier::fromString('issuer'));
        $cert = $tbsCert->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertSame(TBSCertificate::VERSION_2, $cert->tbsCertificate()->version());
    }

    #[Test]
    public function version3()
    {
        $tbsCert = self::$_tbsCert->withExtensions(
            Extensions::create(KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE))
        );
        $cert = $tbsCert->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertSame(TBSCertificate::VERSION_3, $cert->tbsCertificate()->version());
    }
}
