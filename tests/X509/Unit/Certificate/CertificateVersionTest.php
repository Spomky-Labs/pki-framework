<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
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
    private static $_privateKeyInfo;

    private static $_tbsCert;

    public static function setUpBeforeClass(): void
    {
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $subject = Name::fromString('cn=Test Subject');
        $issuer = Name::fromString('cn=Test Issuer');
        $pki = self::$_privateKeyInfo->publicKeyInfo();
        $validity = Validity::fromStrings('now', 'now + 1 day', 'UTC');
        self::$_tbsCert = new TBSCertificate($subject, $pki, $issuer, $validity);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_privateKeyInfo = null;
        self::$_tbsCert = null;
    }

    /**
     * @test
     */
    public function version1()
    {
        $cert = self::$_tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_privateKeyInfo);
        static::assertEquals($cert->tbsCertificate()->version(), TBSCertificate::VERSION_1);
    }

    /**
     * @test
     */
    public function version2SubjectUID()
    {
        $tbsCert = self::$_tbsCert->withSubjectUniqueID(UniqueIdentifier::fromString('subject'));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_privateKeyInfo);
        static::assertEquals($cert->tbsCertificate()->version(), TBSCertificate::VERSION_2);
    }

    /**
     * @test
     */
    public function version2IssuerUID()
    {
        $tbsCert = self::$_tbsCert->withIssuerUniqueID(UniqueIdentifier::fromString('issuer'));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_privateKeyInfo);
        static::assertEquals($cert->tbsCertificate()->version(), TBSCertificate::VERSION_2);
    }

    /**
     * @test
     */
    public function version2BothUID()
    {
        $tbsCert = self::$_tbsCert->withSubjectUniqueID(
            UniqueIdentifier::fromString('subject')
        )->withIssuerUniqueID(UniqueIdentifier::fromString('issuer'));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_privateKeyInfo);
        static::assertEquals($cert->tbsCertificate()->version(), TBSCertificate::VERSION_2);
    }

    /**
     * @test
     */
    public function version3()
    {
        $tbsCert = self::$_tbsCert->withExtensions(
            new Extensions(new KeyUsageExtension(true, KeyUsageExtension::DIGITAL_SIGNATURE))
        );
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_privateKeyInfo);
        static::assertEquals($cert->tbsCertificate()->version(), TBSCertificate::VERSION_3);
    }
}
