<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\PathValidation;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * @internal
 */
final class IntermediateTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const INTERM_NAME = 'cn=Interm';

    public const CERT_NAME = 'cn=EE';

    private static $_caKey;

    private static $_ca;

    private static $_intermKey;

    private static $_interm;

    private static $_certKey;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        self::$_intermKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem')
        )->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
        // create CA certificate
        $tbs = TBSCertificate::create(
            Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withAdditionalExtensions(
            BasicConstraintsExtension::create(true, true),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN)
        );
        self::$_ca = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
        // create intermediate certificate
        $tbs = TBSCertificate::create(
            Name::fromString(self::INTERM_NAME),
            self::$_intermKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(BasicConstraintsExtension::create(true, true));
        self::$_interm = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
        // create end-entity certificate
        $tbs = TBSCertificate::create(
            Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::INTERM_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate(self::$_interm);
        self::$_cert = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_intermKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_intermKey = null;
        self::$_interm = null;
        self::$_certKey = null;
        self::$_cert = null;
    }

    /**
     * @test
     */
    public function validate()
    {
        $path = CertificationPath::create(self::$_ca, self::$_interm, self::$_cert);
        $result = $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
        static::assertInstanceOf(PathValidationResult::class, $result);
    }
}
