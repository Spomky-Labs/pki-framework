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
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * Two limitations in CertificationPathBuilder::findIssuers().
 *
 * A certificate without an authorityKeyIdentifier could never be chained, which pushed integrators towards
 * CertificationPath::create(), the unsafe constructor. And the lookup index was keyed on the subjectKeyIdentifier
 * a certificate claims for itself, which is arbitrary data never checked against the key: one extra certificate
 * in a peer-supplied bundle was enough to deny validation of a perfectly good chain.
 *
 * @internal
 */
final class PathBuildingResolutionTest extends TestCase
{
    private static ?PrivateKeyInfo $caKey = null;

    private static ?PrivateKeyInfo $leafKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$caKey = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))
            ->privateKeyInfo();
        self::$leafKey = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))
            ->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$caKey = null;
        self::$leafKey = null;
    }

    #[Test]
    public function aCertificateWithoutAnAuthorityKeyIdentifierIsChained(): void
    {
        $root = self::root();
        $leaf = self::leaf($root, false);

        static::assertFalse($leaf->tbsCertificate()->extensions()->hasAuthorityKeyIdentifier());

        $path = CertificationPath::toTarget($leaf, CertificateBundle::create($root));

        static::assertCount(2, $path);
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::defaultConfig()->withTrustAnchor($root))
        );
    }

    #[Test]
    public function aCertificateWithAnAuthorityKeyIdentifierIsStillChained(): void
    {
        $root = self::root();
        $leaf = self::leaf($root, true);

        $path = CertificationPath::toTarget($leaf, CertificateBundle::create($root));

        static::assertCount(2, $path);
        static::assertTrue($path->startsWith($root));
    }

    #[Test]
    public function aClaimedSubjectKeyIdentifierDoesNotDisplaceTheRealIssuer(): void
    {
        // The rogue certificate repeats the root's subject DN and its subjectKeyIdentifier, but holds another
        // key. It used to take the root's place in the lookup index, so the builder returned the rogue path and
        // validation failed on the signature.
        $root = self::root();
        $leaf = self::leaf($root, true);
        $rogue = self::rogueTwinOf($root);

        $path = CertificationPath::toTarget($leaf, CertificateBundle::create($rogue, $root));

        static::assertTrue($path->startsWith($root));
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::defaultConfig()->withTrustAnchor($root))
        );
    }

    #[Test]
    public function theRealIssuerIsAmongTheCandidatesWhateverTheBundleOrder(): void
    {
        $root = self::root();
        $leaf = self::leaf($root, true);
        $rogue = self::rogueTwinOf($root);

        foreach ([[$rogue, $root], [$root, $rogue]] as $certs) {
            $found = CertificateBundle::create(...$certs)->allBySubjectKeyIdentifier(
                $root->tbsCertificate()
                    ->extensions()
                    ->subjectKeyIdentifier()
                    ->keyIdentifier()
            );

            static::assertCount(2, $found, 'both candidates must be offered, not one of them silently dropped');
        }

        static::assertTrue(
            CertificationPath::toTarget($leaf, CertificateBundle::create($rogue, $root))->startsWith($root)
        );
    }

    private static function root(): Certificate
    {
        $subject = Name::fromString('cn=Corp Root CA');

        return TBSCertificate::create(
            $subject,
            self::$caKey->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 10 years')
        )
            ->withSerialNumber('1')
            ->withAdditionalExtensions(
                BasicConstraintsExtension::create(true, true),
                SubjectKeyIdentifierExtension::create(false, self::$caKey->publicKeyInfo()->keyIdentifier())
            )
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$caKey);
    }

    /**
     * A certificate that repeats the root's subject DN and its declared key identifier, but holds another key.
     */
    private static function rogueTwinOf(Certificate $root): Certificate
    {
        $subject = $root->tbsCertificate()
            ->subject();

        return TBSCertificate::create(
            $subject,
            self::$leafKey->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 10 years')
        )
            ->withSerialNumber('99')
            ->withAdditionalExtensions(
                BasicConstraintsExtension::create(true, true),
                SubjectKeyIdentifierExtension::create(
                    false,
                    $root->tbsCertificate()
                        ->extensions()
                        ->subjectKeyIdentifier()
                        ->keyIdentifier()
                )
            )
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$leafKey);
    }

    private static function leaf(Certificate $root, bool $withAuthorityKeyIdentifier): Certificate
    {
        $tbs = TBSCertificate::create(
            Name::fromString('cn=leaf'),
            self::$leafKey->publicKeyInfo(),
            $root->tbsCertificate()
                ->subject(),
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        )->withSerialNumber('2');

        if ($withAuthorityKeyIdentifier) {
            $tbs = $tbs->withIssuerCertificate($root);
        }

        return $tbs->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$caKey);
    }
}
