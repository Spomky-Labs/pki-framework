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
use SpomkyLabs\Pki\X501\StringPrep\Exception\StringPreparationException;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathBuildingException;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathBuilding\CertificationPathBuilder;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * A name that cannot be prepared for comparison fails the path validation and the path building as such.
 *
 * The Prohibit step of RFC 4518 refuses the code points that have no prepared form: a private use character, a
 * non-character or a replacement character cannot be normalised or case folded, and what a converter does with
 * them instead is what makes two different names collapse onto one. Refusing them is what keeps a name from
 * escaping an excluded subtree, so the comparison must fail rather than answer "not equal".
 *
 * That failure used to travel out of PathValidator::validate() and CertificationPathBuilder::allPathsToTarget()
 * as the comparison's own exception, which is neither PathValidationException nor PathBuildingException. An
 * application catching what those methods document caught nothing, and a single certificate carrying such a name
 * -- in a bundle a peer supplies, in every common scenario -- turned a handled validation failure into an
 * unhandled one.
 *
 * @internal
 */
final class UncomparableNameTest extends TestCase
{
    /**
     * A private use code point: it denotes no character, so it has no prepared form.
     *
     * @var string
     */
    private const UNCOMPARABLE = "\u{E000}";

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
    public function theComparisonItselfStillFailsClosed(): void
    {
        // the guard being restored here is the exception type at the boundary, not the refusal: a name with no
        // prepared form must never be reported as simply "not equal"
        $this->expectException(StringPreparationException::class);

        Name::fromString('cn=Acme' . self::UNCOMPARABLE)->equals(Name::fromString('cn=Other'));
    }

    #[Test]
    public function validationReportsItAsAPathValidationException(): void
    {
        [$root, $leaf] = self::path();

        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('cannot be prepared for comparison');

        CertificationPath::create($root, $leaf)
            ->validate(PathValidationConfig::defaultConfig()->withTrustAnchor($root));
    }

    #[Test]
    public function pathBuildingReportsItAsAPathBuildingException(): void
    {
        [$root, $leaf] = self::path();

        $this->expectException(PathBuildingException::class);
        $this->expectExceptionMessage('cannot be prepared for comparison');

        CertificationPathBuilder::create(CertificateBundle::create($root))
            ->allPathsToTarget($leaf, CertificateBundle::create($leaf));
    }

    /**
     * A root whose subject carries the uncomparable name, and a leaf naming it as its issuer.
     *
     * @return array{Certificate, Certificate}
     */
    private static function path(): array
    {
        $subject = Name::fromString('cn=Test Root' . self::UNCOMPARABLE);
        $validity = Validity::fromStrings('now - 1 hour', 'now + 1 hour');

        $root = TBSCertificate::create($subject, self::$key->publicKeyInfo(), $subject, $validity)
            ->withSerialNumber('1')
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true))
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key);

        $leaf = TBSCertificate::create(
            Name::fromString('cn=leaf'),
            self::$key->publicKeyInfo(),
            $subject,
            $validity
        )
            ->withSerialNumber('2')
            ->withIssuerCertificate($root)
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key);

        return [$root, $leaf];
    }
}
