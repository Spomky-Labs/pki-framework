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
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Cover case where valid policy tree gets fully pruned when anyPolicy is inhibited.
 *
 * @internal
 */
final class PolicyProcessPruneTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const CERT_NAME = 'cn=EE';

    private static $_caKey;

    private static $_ca;

    private static $_certKey;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(
            Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true, 1),
            new InhibitAnyPolicyExtension(true, 0),
            new CertificatePoliciesExtension(true, new PolicyInformation(PolicyInformation::OID_ANY_POLICY))
        );
        self::$_ca = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(
            Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new CertificatePoliciesExtension(true, new PolicyInformation(PolicyInformation::OID_ANY_POLICY))
        );
        self::$_cert = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_certKey = null;
        self::$_cert = null;
    }

    /**
     * @test
     */
    public function validate()
    {
        $path = CertificationPath::create(self::$_ca, self::$_cert);
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3);
        $config = $config->withExplicitPolicy(true);
        $this->expectException(PathValidationException::class);
        $path->validate($config);
    }
}
