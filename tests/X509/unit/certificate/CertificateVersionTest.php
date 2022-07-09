<?php

declare(strict_types=1);

namespace unit\certificate;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\Certificate\Extension\KeyUsageExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\Certificate\TBSCertificate;
use Sop\X509\Certificate\UniqueIdentifier;
use Sop\X509\Certificate\Validity;

/**
 * @group certificate
 *
 * @internal
 */
class CertificateVersionTest extends TestCase
{
    private static $_privateKeyInfo;

    private static $_tbsCert;

    public static function setUpBeforeClass(): void
    {
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
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

    public function testVersion1()
    {
        $cert = self::$_tbsCert->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privateKeyInfo);
        $this->assertEquals($cert->tbsCertificate()
            ->version(), TBSCertificate::VERSION_1);
    }

    public function testVersion2SubjectUID()
    {
        $tbsCert = self::$_tbsCert->withSubjectUniqueID(
            UniqueIdentifier::fromString('subject'));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privateKeyInfo);
        $this->assertEquals($cert->tbsCertificate()
            ->version(), TBSCertificate::VERSION_2);
    }

    public function testVersion2IssuerUID()
    {
        $tbsCert = self::$_tbsCert->withIssuerUniqueID(
            UniqueIdentifier::fromString('issuer'));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privateKeyInfo);
        $this->assertEquals($cert->tbsCertificate()
            ->version(), TBSCertificate::VERSION_2);
    }

    public function testVersion2BothUID()
    {
        $tbsCert = self::$_tbsCert->withSubjectUniqueID(
            UniqueIdentifier::fromString('subject'))->withIssuerUniqueID(
            UniqueIdentifier::fromString('issuer'));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privateKeyInfo);
        $this->assertEquals($cert->tbsCertificate()
            ->version(), TBSCertificate::VERSION_2);
    }

    public function testVersion3()
    {
        $tbsCert = self::$_tbsCert->withExtensions(
            new Extensions(
                new KeyUsageExtension(true, KeyUsageExtension::DIGITAL_SIGNATURE)));
        $cert = $tbsCert->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_privateKeyInfo);
        $this->assertEquals($cert->tbsCertificate()
            ->version(), TBSCertificate::VERSION_3);
    }
}
