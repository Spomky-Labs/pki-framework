<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Workflow;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;

/**
 * @internal
 */
final class RequestToCertTest extends TestCase
{
    private static $_issuerKey;

    private static $_subjectKey;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerKey = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        self::$_subjectKey = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuerKey = null;
        self::$_subjectKey = null;
    }

    /**
     * @test
     */
    public function createCA()
    {
        $name = Name::fromString('cn=Issuer');
        $validity = Validity::fromStrings('2016-05-02 12:00:00', '2016-05-03 12:00:00');
        $pki = self::$_issuerKey->publicKeyInfo();
        $tbs_cert = new TBSCertificate($name, $pki, $name, $validity);
        $tbs_cert = $tbs_cert->withExtensions(
            Extensions::create(
                new BasicConstraintsExtension(true, true),
                SubjectKeyIdentifierExtension::create(false, $pki->keyIdentifier()),
                KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE | KeyUsageExtension::KEY_CERT_SIGN)
            )
        );
        $algo = SHA256WithRSAEncryptionAlgorithmIdentifier::create();
        $cert = $tbs_cert->sign($algo, self::$_issuerKey);
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @test
     */
    public function createRequest()
    {
        $subject = Name::fromString('cn=Subject');
        $pkinfo = self::$_subjectKey->publicKeyInfo();
        $cri = CertificationRequestInfo::create($subject, $pkinfo);
        $cri = $cri->withExtensionRequest(Extensions::create(new BasicConstraintsExtension(true, false)));
        $algo = ECDSAWithSHA1AlgorithmIdentifier::create();
        $csr = $cri->sign($algo, self::$_subjectKey);
        static::assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }

    /**
     * @depends createRequest
     * @depends createCA
     *
     * @test
     */
    public function issueCertificate(CertificationRequest $csr, Certificate $ca_cert)
    {
        $tbs_cert = TBSCertificate::fromCSR($csr)->withIssuerCertificate($ca_cert);
        $validity = Validity::fromStrings('2016-05-02 12:00:00', '2016-05-02 13:00:00');
        $tbs_cert = $tbs_cert->withValidity($validity);
        $tbs_cert = $tbs_cert->withAdditionalExtensions(
            KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE | KeyUsageExtension::KEY_ENCIPHERMENT),
            new BasicConstraintsExtension(true, false)
        );
        $algo = SHA512WithRSAEncryptionAlgorithmIdentifier::create();
        $cert = $tbs_cert->sign($algo, self::$_issuerKey);
        static::assertInstanceOf(Certificate::class, $cert);
        return $cert;
    }

    /**
     * @depends createCA
     * @depends issueCertificate
     *
     * @test
     */
    public function buildPath(Certificate $ca, Certificate $cert)
    {
        $path = CertificationPath::fromTrustAnchorToTarget($ca, $cert);
        static::assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function validatePath(CertificationPath $path)
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(new DateTimeImmutable('2016-05-02 12:30:00'));
        $result = $path->validate($config);
        static::assertInstanceOf(PathValidationResult::class, $result);
    }
}
