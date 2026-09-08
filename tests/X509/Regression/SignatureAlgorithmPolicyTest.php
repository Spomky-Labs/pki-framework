<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use DateTimeImmutable;
use InvalidArgumentException;
use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * The validator used to accept MD4, MD5 and SHA-1 with no way for the application to say no.
 *
 * @internal
 */
final class SignatureAlgorithmPolicyTest extends TestCase
{
    private static ?PrivateKeyInfo $key = null;

    private static ?PrivateKeyInfo $weakKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$key = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))
            ->privateKeyInfo();
        // 1024 bits, the smallest RSA key shipped with the test assets.
        self::$weakKey = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))
            ->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$key = null;
        self::$weakKey = null;
    }

    #[Test]
    public function md5IsRejectedByDefault(): void
    {
        [$root, $leaf] = self::buildPath(MD5WithRSAEncryptionAlgorithmIdentifier::create());

        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('is not allowed');
        CertificationPath::create($root, $leaf)
            ->validate(PathValidationConfig::create(new DateTimeImmutable(), 5));
    }

    /**
     * @return Iterator<string, array{SignatureAlgorithmIdentifier}>
     */
    public static function acceptedByDefaultProvider(): Iterator
    {
        // Kept in the default set: legacy PKIs still rely on it, and cutting them off silently is not this
        // library's call. HARDENED_ALLOWED_SIGNATURE_ALGORITHMS refuses it.
        yield 'SHA-1' => [SHA1WithRSAEncryptionAlgorithmIdentifier::create()];
        yield 'SHA-256' => [SHA256WithRSAEncryptionAlgorithmIdentifier::create()];
    }

    #[Test]
    #[DataProvider('acceptedByDefaultProvider')]
    public function theDefaultSetKeepsWorkingChainsWorking(SignatureAlgorithmIdentifier $algo): void
    {
        [$root, $leaf] = self::buildPath($algo);

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)
                ->validate(PathValidationConfig::create(new DateTimeImmutable(), 5))
        );
    }

    #[Test]
    public function theHardenedSetRefusesSha1(): void
    {
        [$root, $leaf] = self::buildPath(SHA1WithRSAEncryptionAlgorithmIdentifier::create());

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withAllowedSignatureAlgorithms(...PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS);

        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('is not allowed');
        CertificationPath::create($root, $leaf)->validate($config);
    }

    #[Test]
    public function theHardenedSetStillAcceptsSha256(): void
    {
        [$root, $leaf] = self::buildPath(SHA256WithRSAEncryptionAlgorithmIdentifier::create());

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withAllowedSignatureAlgorithms(...PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS);

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)->validate($config)
        );
    }

    #[Test]
    public function md5CannotBeReenabledByAccidentAndCanBeOnPurpose(): void
    {
        [$root, $leaf] = self::buildPath(MD5WithRSAEncryptionAlgorithmIdentifier::create());

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withAllowedSignatureAlgorithms(
                ...array_merge(
                    PathValidationConfig::DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS,
                    [AlgorithmIdentifier::OID_MD5_WITH_RSA_ENCRYPTION]
                )
            );

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)->validate($config)
        );
    }

    #[Test]
    public function narrowingTheSetRejectsEverythingElse(): void
    {
        [$root, $leaf] = self::buildPath(SHA256WithRSAEncryptionAlgorithmIdentifier::create());

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withAllowedSignatureAlgorithms(AlgorithmIdentifier::OID_ED25519);

        $this->expectException(PathValidationException::class);
        CertificationPath::create($root, $leaf)->validate($config);
    }

    #[Test]
    public function theTwoSetsDifferOnlyBySha1(): void
    {
        $default = PathValidationConfig::DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS;
        $hardened = PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS;

        foreach ([
            AlgorithmIdentifier::OID_MD2_WITH_RSA_ENCRYPTION,
            AlgorithmIdentifier::OID_MD4_WITH_RSA_ENCRYPTION,
            AlgorithmIdentifier::OID_MD5_WITH_RSA_ENCRYPTION,
        ] as $oid) {
            static::assertNotContains($oid, $default, 'broken digests must be out of the default set');
        }

        static::assertSame(
            [AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, AlgorithmIdentifier::OID_ECDSA_WITH_SHA1],
            array_values(array_diff($default, $hardened))
        );
        static::assertSame($default, PathValidationConfig::defaultConfig()->allowedSignatureAlgorithms());
    }

    #[Test]
    public function aKeyBelowTheConfiguredFloorIsRejected(): void
    {
        // The advisory's RSA-512 case: the smallest key in the assets is 1024 bits, so the floor is raised by one
        // bit rather than shrinking the key. It is the same comparison the default makes for a 512 bit modulus.
        [$root, $leaf] = self::buildPath(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$weakKey);

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withMinimumRSAKeySize(PathValidationConfig::DEFAULT_MINIMUM_RSA_KEY_SIZE + 1);

        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('below the minimum');
        CertificationPath::create($root, $leaf)->validate($config);
    }

    #[Test]
    public function theHardenedFloorRefusesA1024BitKey(): void
    {
        [$root, $leaf] = self::buildPath(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$weakKey);

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withMinimumRSAKeySize(PathValidationConfig::HARDENED_MINIMUM_RSA_KEY_SIZE);

        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('below the minimum');
        CertificationPath::create($root, $leaf)->validate($config);
    }

    #[Test]
    public function the1024BitKeyStillValidatesOnTheDefaultFloor(): void
    {
        [$root, $leaf] = self::buildPath(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$weakKey);

        static::assertSame(1024, PathValidationConfig::DEFAULT_MINIMUM_RSA_KEY_SIZE);
        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)
                ->validate(PathValidationConfig::create(new DateTimeImmutable(), 5))
        );
    }

    #[Test]
    public function theCheckCanBeDisabled(): void
    {
        [$root, $leaf] = self::buildPath(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$weakKey);

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)->withMinimumRSAKeySize(0);

        static::assertSame(0, $config->minimumRSAKeySize());
        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)->validate($config)
        );
    }

    #[Test]
    public function aNegativeFloorIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PathValidationConfig::defaultConfig()->withMinimumRSAKeySize(-1);
    }

    #[Test]
    public function ecPathsAreNotAffectedByTheRsaFloor(): void
    {
        $key = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'))->privateKeyInfo();
        [$root, $leaf] = self::buildPath(ECDSAWithSHA256AlgorithmIdentifier::create(), $key);

        $config = PathValidationConfig::create(new DateTimeImmutable(), 5)
            ->withMinimumRSAKeySize(PathValidationConfig::HARDENED_MINIMUM_RSA_KEY_SIZE);

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)->validate($config)
        );
    }

    /**
     * @return array{Certificate, Certificate}
     */
    private static function buildPath(SignatureAlgorithmIdentifier $algo, ?PrivateKeyInfo $key = null): array
    {
        $key ??= self::$key;
        $validity = Validity::fromStrings('now - 1 hour', 'now + 1 hour');

        $root = TBSCertificate::create(
            Name::fromString('cn=Test Root'),
            $key->publicKeyInfo(),
            Name::fromString('cn=Test Root'),
            $validity
        )
            ->withSerialNumber('1')
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, true))
            ->sign($algo, $key);

        $leaf = TBSCertificate::create(
            Name::fromString('cn=leaf'),
            $key->publicKeyInfo(),
            $root->tbsCertificate()
                ->subject(),
            $validity
        )
            ->withSerialNumber('2')
            ->sign($algo, $key);

        return [$root, $leaf];
    }
}
