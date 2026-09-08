<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\ACValidationConfig;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\ACValidator;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\Exception\ACValidationException;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Three hardening items in the attribute certificate validator.
 *
 * The evaluation clock was snapshotted at construction, so a config object shared by a DI container or held
 * across requests in a worker runtime kept validating expired credentials for the lifetime of the process. RFC
 * 5755 section 5 check 4 was neither implemented nor documented as the caller's job. And the caller's maximum
 * path length was overridden for both paths.
 *
 * @internal
 */
final class AttributeCertificateValidationTest extends TestCase
{
    private static ?CertificationPath $holderPath = null;

    private static ?CertificationPath $issuerPath = null;

    private static ?Certificate $issuer = null;

    private static ?Certificate $holder = null;

    private static ?AttributeCertificate $ac = null;

    public static function setUpBeforeClass(): void
    {
        $rootCa = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $interms = CertificateBundle::fromPEMBundle(
            PEMBundle::fromFile(TEST_ASSETS_DIR . '/certs/intermediate-bundle.pem')
        );
        self::$holder = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        self::$issuer = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $issuerKey = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'));

        self::$holderPath = CertificationPath::fromTrustAnchorToTarget($rootCa, self::$holder, $interms);
        self::$issuerPath = CertificationPath::fromTrustAnchorToTarget($rootCa, self::$issuer, $interms);

        self::$ac = AttributeCertificateInfo::create(
            Holder::fromPKC(self::$holder),
            AttCertIssuer::fromPKC(self::$issuer),
            AttCertValidityPeriod::fromStrings('2025-01-01', '2025-01-01 + 1 hour'),
            Attributes::create()
        )->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $issuerKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$holderPath = null;
        self::$issuerPath = null;
        self::$issuer = null;
        self::$holder = null;
        self::$ac = null;
    }

    #[Test]
    public function theEvaluationClockIsNotSnapshottedAtConstruction(): void
    {
        $config = ACValidationConfig::create(self::$holderPath, self::$issuerPath);

        $first = $config->evaluationTime();
        usleep(1100);
        $second = $config->evaluationTime();

        static::assertGreaterThan($first, $second, 'the clock must be read on every evaluation');
    }

    #[Test]
    public function anExplicitEvaluationTimeIsStillPinned(): void
    {
        $pinned = new DateTimeImmutable('2025-01-01', new DateTimeZone('UTC'));
        $config = ACValidationConfig::create(self::$holderPath, self::$issuerPath)->withEvaluationTime($pinned);

        static::assertSame($pinned, $config->evaluationTime());
        static::assertSame($pinned, $config->evaluationTime());
    }

    #[Test]
    public function aTrustedAttributeAuthorityListIsEnforced(): void
    {
        $config = self::pinnedConfig()->withTrustedAttributeAuthorities(self::$issuer);

        static::assertInstanceOf(AttributeCertificate::class, ACValidator::create(self::$ac, $config)->validate());
    }

    #[Test]
    public function anEndEntityCertificateThatIsNotOnTheListIsRefused(): void
    {
        // Without the list the validator accepts whatever end-entity certificate the issuer path ends in, so a
        // caller who locates the attribute authority by matching the issuer name against a bundle turns every
        // end-entity certificate under the trust anchor into an attribute authority.
        $config = self::pinnedConfig()->withTrustedAttributeAuthorities(self::$holder);

        $this->expectException(ACValidationException::class);
        $this->expectExceptionMessage('not a trusted attribute authority');
        ACValidator::create(self::$ac, $config)->validate();
    }

    #[Test]
    public function withoutAListTheCheckIsSkippedAsBefore(): void
    {
        static::assertNull(self::pinnedConfig()->trustedAttributeAuthorities());
        static::assertInstanceOf(
            AttributeCertificate::class,
            ACValidator::create(self::$ac, self::pinnedConfig())->validate()
        );
    }

    #[Test]
    public function theCallersMaximumPathLengthIsHonoured(): void
    {
        // withMaxLength(count($path)) used to be applied to both paths, which made this setting a no-op.
        $config = self::pinnedConfig()->withPathValidationConfig(
            PathValidationConfig::defaultConfig()->withMaxLength(0)
        );

        $this->expectException(ACValidationException::class);
        $this->expectExceptionMessage("Failed to validate holder PKC's certification path.");
        ACValidator::create(self::$ac, $config)->validate();
    }

    #[Test]
    public function aGenerousLimitStillValidates(): void
    {
        $config = self::pinnedConfig()->withPathValidationConfig(
            PathValidationConfig::defaultConfig()->withMaxLength(5)
        );

        static::assertInstanceOf(AttributeCertificate::class, ACValidator::create(self::$ac, $config)->validate());
    }

    private static function pinnedConfig(): ACValidationConfig
    {
        return ACValidationConfig::create(self::$holderPath, self::$issuerPath)
            ->withEvaluationTime(new DateTimeImmutable('2025-01-01', new DateTimeZone('UTC')));
    }
}
