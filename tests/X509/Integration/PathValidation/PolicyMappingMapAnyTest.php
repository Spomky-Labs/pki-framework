<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\PathValidation;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappingsExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\ValidatorState;
use SpomkyLabs\Pki\X509\CertificationPath\Policy\PolicyNode;
use SpomkyLabs\Pki\X509\CertificationPath\Policy\PolicyTree;

/**
 * @internal
 */
final class PolicyMappingMapAnyTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const CERT_NAME = 'cn=EE';

    private static ?PrivateKeyInfo $_caKey = null;

    private static ?Certificate $_ca = null;

    private static ?PrivateKeyInfo $_certKey = null;

    private static ?Certificate $_cert = null;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
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
            CertificatePoliciesExtension::create(true, PolicyInformation::create(PolicyInformation::OID_ANY_POLICY)),
            PolicyMappingsExtension::create(true, PolicyMapping::create('1.3.6.1.3.1', '1.3.6.1.3.2'))
        );
        self::$_ca = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
        // create end-entity certificate
        $tbs = TBSCertificate::create(
            Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            CertificatePoliciesExtension::create(true, PolicyInformation::create('1.3.6.1.3.2'))
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

    #[Test]
    public function validate()
    {
        $path = CertificationPath::create(self::$_ca, self::$_cert);
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3);
        $config = $config->withExplicitPolicy(true);
        $result = $path->validate($config);
        static::assertEquals('1.3.6.1.3.2', $result->policies()[0]->oid());
    }

    #[Test]
    public function coverLogicException()
    {
        $tree = PolicyTree::create(PolicyNode::anyPolicyNode()->addChild(PolicyNode::anyPolicyNode()));
        $refl = new ReflectionClass($tree);
        $mtd = $refl->getMethod('_applyAnyPolicyMapping');
        $mtd->setAccessible(true);
        $state = ValidatorState::initialize(PathValidationConfig::defaultConfig(), self::$_ca, 3);
        $mtd->invoke($tree, self::$_cert, $state, '1.3.6.1.3', []);
        static::assertTrue(true);
    }
}
