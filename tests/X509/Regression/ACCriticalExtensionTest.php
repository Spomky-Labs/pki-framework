<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\ACValidationConfig;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\ACValidator;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\Exception\ACValidationException;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * RFC 5755 section 5, check 7 requires an attribute certificate carrying an unsupported critical extension to be
 * rejected. The validator ran the holder, issuer, profile, time and targeting checks and never looked at extension
 * criticality, so an attribute authority that narrowed a credential with a critical extension had that restriction
 * silently discarded and the attributes granted unconditionally.
 *
 * @internal
 */
final class ACCriticalExtensionTest extends TestCase
{
    private const ROLE = 'urn:administrator';

    private const UNKNOWN_OID = '1.3.6.1.4.1.99999.1';

    private static ?PrivateKeyInfo $caKey = null;

    private static ?PrivateKeyInfo $aaKey = null;

    private static ?PrivateKeyInfo $holderKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$caKey = self::key('acme-ca-rsa');
        self::$aaKey = self::key('acme-interm-rsa');
        self::$holderKey = self::key('acme-rsa');
    }

    public static function tearDownAfterClass(): void
    {
        self::$caKey = null;
        self::$aaKey = null;
        self::$holderKey = null;
    }

    #[Test]
    public function anUnsupportedCriticalExtensionIsRejected(): void
    {
        $this->expectException(ACValidationException::class);
        $this->expectExceptionMessage('unhandled critical extension');
        self::validate(self::attributeCertificate(true));
    }

    #[Test]
    public function theApplicationMayDeclareThatItHandlesTheExtension(): void
    {
        $result = self::validate(
            self::attributeCertificate(true),
            static fn (ACValidationConfig $c): ACValidationConfig => $c->withAdditionalCriticalExtensions(
                self::UNKNOWN_OID
            )
        );
        static::assertInstanceOf(AttributeCertificate::class, $result);
    }

    #[Test]
    public function aNonCriticalUnknownExtensionIsStillAccepted(): void
    {
        static::assertInstanceOf(AttributeCertificate::class, self::validate(self::attributeCertificate(false)));
    }

    #[Test]
    public function anAttributeCertificateWithNoExtensionsIsStillAccepted(): void
    {
        static::assertInstanceOf(AttributeCertificate::class, self::validate(self::attributeCertificate(null)));
    }

    private static function validate(AttributeCertificate $ac, ?callable $tweak = null): AttributeCertificate
    {
        [$root, $aa, $holder] = self::chain();
        $config = ACValidationConfig::create(
            CertificationPath::create($root, $holder),
            CertificationPath::create($root, $aa)
        )
            ->withPathValidationConfig(PathValidationConfig::create(new DateTimeImmutable('2026-01-01'), 3))
            ->withEvaluationTime(new DateTimeImmutable('2026-01-01'));
        if ($tweak !== null) {
            $config = $tweak($config);
        }

        return ACValidator::create($ac, $config)->validate();
    }

    private static function attributeCertificate(?bool $critical): AttributeCertificate
    {
        [, $aa, $holder] = self::chain();
        $acinfo = AttributeCertificateInfo::create(
            Holder::create(IssuerSerial::fromPKC($holder)),
            AttCertIssuer::fromPKC($aa),
            AttCertValidityPeriod::fromStrings('2025-01-01 12:00:00 UTC', '2035-01-01 12:00:00 UTC'),
            Attributes::fromAttributeValues(RoleAttributeValue::fromString(self::ROLE))
        )->withSerialNumber(1);
        if ($critical !== null) {
            $acinfo = $acinfo->withAdditionalExtensions(
                UnknownExtension::create(self::UNKNOWN_OID, $critical, NullType::create())
            );
        }

        return $acinfo->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$aaKey);
    }

    /**
     * @return array{Certificate, Certificate, Certificate}
     */
    private static function chain(): array
    {
        $root = self::certificate('cn=Root', self::$caKey, null, self::$caKey, Extensions::create(
            BasicConstraintsExtension::create(true, true),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN)
        ));
        // an attribute authority is an end entity that may sign, never a CA
        $aa = self::certificate('cn=AA', self::$aaKey, 'cn=Root', self::$caKey, Extensions::create(
            BasicConstraintsExtension::create(true, false),
            KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE)
        ));
        $holder = self::certificate('cn=Holder', self::$holderKey, 'cn=Root', self::$caKey, Extensions::create(
            BasicConstraintsExtension::create(true, false)
        ));

        return [$root, $aa, $holder];
    }

    private static function certificate(
        string $subject,
        PrivateKeyInfo $subjectKey,
        ?string $issuer,
        PrivateKeyInfo $issuerKey,
        Extensions $extensions
    ): Certificate {
        $tbs = TBSCertificate::create(
            Name::fromString($subject),
            $subjectKey->publicKeyInfo(),
            Name::fromString($issuer ?? $subject),
            Validity::fromStrings('2024-01-01 12:00:00 UTC', '2034-01-01 12:00:00 UTC')
        )
            ->withExtensions($extensions)
            ->withSerialNumber(1);

        return $tbs->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $issuerKey);
    }

    private static function key(string $name): PrivateKeyInfo
    {
        return PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/' . $name . '.pem'))
            ->privateKeyInfo();
    }
}
