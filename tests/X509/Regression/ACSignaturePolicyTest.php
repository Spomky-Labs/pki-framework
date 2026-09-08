<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
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
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * ACValidator path-validated the holder and issuer chains under a PathValidationConfig carrying the acceptable
 * signature algorithms and the smallest acceptable RSA modulus, then verified the attribute certificate's own
 * signature by handing the algorithm straight to the crypto engine, consulting neither setting. The signature that
 * actually carries the authorisation was the one signature the policy did not cover, and the crypto engine's digest
 * map includes MD4, MD5 and SHA-1.
 *
 * @internal
 */
final class ACSignaturePolicyTest extends TestCase
{
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
    public function anMD5SignedAttributeCertificateIsRejectedUnderTheDefaultPolicy(): void
    {
        $this->expectException(ACValidationException::class);
        $this->expectExceptionMessage('is not allowed');
        self::validate(self::attributeCertificate(MD5WithRSAEncryptionAlgorithmIdentifier::create()));
    }

    #[Test]
    public function theCheckAppliesToTheAttributeCertificateAndNotOnlyToThePaths(): void
    {
        // every certificate of both paths is signed with SHA-256, so the hardened set leaves them untouched and
        // only the attribute certificate's own SHA-1 signature is refused
        $this->expectException(ACValidationException::class);
        $this->expectExceptionMessage('is not allowed');
        self::validate(
            self::attributeCertificate(SHA1WithRSAEncryptionAlgorithmIdentifier::create()),
            static fn (PathValidationConfig $c): PathValidationConfig => $c->withAllowedSignatureAlgorithms(
                ...PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS
            )
        );
    }

    #[Test]
    public function thatSameAttributeCertificateIsAcceptedUnderTheDefaultPolicy(): void
    {
        static::assertInstanceOf(
            AttributeCertificate::class,
            self::validate(self::attributeCertificate(SHA1WithRSAEncryptionAlgorithmIdentifier::create()))
        );
    }

    #[Test]
    public function anAttributeAuthorityKeyBelowTheFloorIsRejected(): void
    {
        // the attribute authority's key is 2048 bits, so a floor above it stands in for a weak key without
        // needing one in the fixtures
        $this->expectException(ACValidationException::class);
        $this->expectExceptionMessage('is below the minimum');
        self::validate(
            self::attributeCertificate(SHA256WithRSAEncryptionAlgorithmIdentifier::create()),
            static fn (PathValidationConfig $c): PathValidationConfig => $c->withMinimumRSAKeySize(4096)
        );
    }

    #[Test]
    public function anAcceptableAttributeCertificateStillValidates(): void
    {
        static::assertInstanceOf(
            AttributeCertificate::class,
            self::validate(self::attributeCertificate(SHA256WithRSAEncryptionAlgorithmIdentifier::create()))
        );
    }

    private static function validate(AttributeCertificate $ac, ?callable $tweak = null): AttributeCertificate
    {
        [$root, $aa, $holder] = self::chain();
        $pathConfig = PathValidationConfig::create(new DateTimeImmutable('2026-01-01'), 3);
        if ($tweak !== null) {
            $pathConfig = $tweak($pathConfig);
        }
        $config = ACValidationConfig::create(
            CertificationPath::create($root, $holder),
            CertificationPath::create($root, $aa)
        )
            ->withPathValidationConfig($pathConfig)
            ->withEvaluationTime(new DateTimeImmutable('2026-01-01'));

        return ACValidator::create($ac, $config)->validate();
    }

    private static function attributeCertificate(SignatureAlgorithmIdentifier $algo): AttributeCertificate
    {
        [, $aa, $holder] = self::chain();

        return AttributeCertificateInfo::create(
            Holder::create(IssuerSerial::fromPKC($holder)),
            AttCertIssuer::fromPKC($aa),
            AttCertValidityPeriod::fromStrings('2025-01-01 12:00:00 UTC', '2035-01-01 12:00:00 UTC'),
            Attributes::fromAttributeValues(RoleAttributeValue::fromString('urn:administrator'))
        )
            ->withSerialNumber(1)
            ->sign($algo, self::$aaKey);
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
        return TBSCertificate::create(
            Name::fromString($subject),
            $subjectKey->publicKeyInfo(),
            Name::fromString($issuer ?? $subject),
            Validity::fromStrings('2024-01-01 12:00:00 UTC', '2034-01-01 12:00:00 UTC')
        )
            ->withExtensions($extensions)
            ->withSerialNumber(1)
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $issuerKey);
    }

    private static function key(string $name): PrivateKeyInfo
    {
        return PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/' . $name . '.pem'))
            ->privateKeyInfo();
    }
}
