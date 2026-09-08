<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\PathValidation;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * Covers RFC 5280 section 6.1.4 (k) for version 1 and version 2 intermediate certificates.
 *
 * Such a certificate carries no extensions, hence neither basicConstraints nor keyUsage. Nothing in it says it may
 * sign certificates, so it must be rejected unless the application vouches for it explicitly.
 *
 * @internal
 */
final class LegacyVersionIntermediateTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const INTERMEDIATE_NAME = 'cn=Legacy Intermediate';

    public const CERT_NAME = 'cn=EE';

    private static ?PrivateKeyInfo $caKey = null;

    private static ?Certificate $ca = null;

    private static ?PrivateKeyInfo $intermediateKey = null;

    private static ?Certificate $v1Intermediate = null;

    private static ?Certificate $v2Intermediate = null;

    private static ?Certificate $cert = null;

    public static function setUpBeforeClass(): void
    {
        self::$caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        self::$intermediateKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem')
        )->privateKeyInfo();
        $certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
        $algo = SHA1WithRSAEncryptionAlgorithmIdentifier::create();
        // root CA, a proper v3 CA certificate
        $tbs = TBSCertificate::create(
            Name::fromString(self::CA_NAME),
            self::$caKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withAdditionalExtensions(BasicConstraintsExtension::create(true, true));
        self::$ca = $tbs->sign($algo, self::$caKey);
        // the root issues a certificate carrying no extension at all, so a v1 end-entity certificate
        $tbs = TBSCertificate::create(
            Name::fromString(self::INTERMEDIATE_NAME),
            self::$intermediateKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        )->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(77);
        self::$v1Intermediate = $tbs->sign($algo, self::$caKey);
        // the same certificate with a unique identifier, which makes it a v2
        self::$v2Intermediate = $tbs->withVersion(TBSCertificate::VERSION_2)
            ->withSubjectUniqueID(UniqueIdentifier::create(BitString::create("\x01")))
            ->sign($algo, self::$caKey);
        // that certificate then signs a leaf for an arbitrary name
        $tbs = TBSCertificate::create(
            Name::fromString(self::CERT_NAME),
            $certKey->publicKeyInfo(),
            Name::fromString(self::INTERMEDIATE_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        )->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(88);
        self::$cert = $tbs->sign($algo, self::$intermediateKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$caKey = null;
        self::$ca = null;
        self::$intermediateKey = null;
        self::$v1Intermediate = null;
        self::$v2Intermediate = null;
        self::$cert = null;
    }

    #[Test]
    public function v1IntermediateIsRejected(): void
    {
        $path = CertificationPath::create(self::$ca, self::$v1Intermediate, self::$cert);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('not a v3 certificate');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function v2IntermediateIsRejected(): void
    {
        $path = CertificationPath::create(self::$ca, self::$v2Intermediate, self::$cert);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('not a v3 certificate');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function v1IntermediateIsAcceptedWhenExplicitlyTrusted(): void
    {
        $path = CertificationPath::create(self::$ca, self::$v1Intermediate, self::$cert);
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3)
            ->withLegacyV1IntermediatesTrusted(true);
        static::assertInstanceOf(PathValidationResult::class, $path->validate($config));
    }
}
