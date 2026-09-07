<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use const E_USER_DEPRECATED;
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
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * validate() refuses to run without an explicit trust anchor only when the path came from fromCertificateChain().
 *
 * The guard was attached to the constructor that was used rather than to the invariant it protects, so a path
 * built with create() on peer material still fell back to using that material's own first certificate as the
 * anchor. Nothing in the result told a chain anchored in the caller's trust store from one anchored in the
 * attacker's. The fallback is now announced, so an application can find the call sites before it is removed.
 *
 * @internal
 */
final class TrustAnchorFallbackTest extends TestCase
{
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
    public function createFallingBackToItsOwnHeadIsAnnounced(): void
    {
        [$root, $leaf] = self::path();

        $deprecations = self::collectDeprecations(
            static fn () => CertificationPath::create($root, $leaf)
                ->validate(PathValidationConfig::defaultConfig())
        );

        static::assertCount(1, $deprecations);
        static::assertStringContainsString('without an explicit trust anchor is deprecated', $deprecations[0]);
    }

    #[Test]
    public function aSingleSelfSignedCertificateValidatingAsItsOwnAnchorIsAnnounced(): void
    {
        [$root] = self::path();

        $deprecations = self::collectDeprecations(
            static fn () => CertificationPath::create($root)->validate(PathValidationConfig::defaultConfig())
        );

        static::assertCount(1, $deprecations);
    }

    #[Test]
    public function namingTheAnchorIsSilent(): void
    {
        [$root, $leaf] = self::path();

        $deprecations = self::collectDeprecations(
            static fn () => CertificationPath::create($root, $leaf)
                ->validate(PathValidationConfig::defaultConfig()->withTrustAnchor($root))
        );

        static::assertSame([], $deprecations);
    }

    #[Test]
    public function aPathBuiltFromATrustListIsSilent(): void
    {
        // toTarget() heads the path with a certificate out of the bundle the caller supplied, so its head is a
        // trust anchor the application chose and there is nothing to warn about.
        [$root, $leaf] = self::path();

        $deprecations = self::collectDeprecations(
            static fn () => CertificationPath::toTarget($leaf, CertificateBundle::create($root))
                ->validate(PathValidationConfig::defaultConfig())
        );

        static::assertSame([], $deprecations);
    }

    /**
     * @return string[]
     */
    private static function collectDeprecations(callable $fn): array
    {
        $collected = [];
        set_error_handler(static function (int $errno, string $message) use (&$collected): bool {
            $collected[] = $message;
            return true;
        }, E_USER_DEPRECATED);

        try {
            $fn();
        } finally {
            restore_error_handler();
        }

        return $collected;
    }

    /**
     * @return array{Certificate, Certificate}
     */
    private static function path(): array
    {
        $subject = Name::fromString('cn=Test Root');
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
