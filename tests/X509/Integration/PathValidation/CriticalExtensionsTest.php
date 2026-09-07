<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\PathValidation;

use function count;
use DateTimeImmutable;
use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\ExtendedKeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\InhibitAnyPolicyExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappingsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * Covers the processing of critical extensions during path validation.
 *
 * RFC 5280 sections 6.1.4 (o) and 6.1.5 (f) require a certificate carrying a critical extension the validator cannot
 * process to be rejected.
 *
 * @internal
 */
final class CriticalExtensionsTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const CERT_NAME = 'cn=EE';

    public const UNKNOWN_OID = '1.3.6.1.4.1.99999.1';

    private static ?PrivateKeyInfo $_caKey = null;

    private static ?PrivateKeyInfo $_certKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_certKey = null;
    }

    /**
     * Critical extensions the validator is able to process.
     *
     * @return Iterator<string, array{Extension}>
     */
    public static function processedCriticalExtensions(): Iterator
    {
        yield 'basicConstraints' => [BasicConstraintsExtension::create(true, false)];
        yield 'keyUsage' => [KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE)];
        yield 'certificatePolicies' => [
            CertificatePoliciesExtension::create(true, PolicyInformation::create('1.3.6.1.3.1')),
        ];
        yield 'policyMappings' => [
            PolicyMappingsExtension::create(true, PolicyMapping::create('1.3.6.1.3.1', '1.3.6.1.3.2')),
        ];
        yield 'policyConstraints' => [PolicyConstraintsExtension::create(true, 3, 3)];
        yield 'inhibitAnyPolicy' => [InhibitAnyPolicyExtension::create(true, 1)];
        yield 'nameConstraints' => [
            NameConstraintsExtension::create(
                true,
                GeneralSubtrees::create(GeneralSubtree::create(DirectoryName::fromDNString('c=FI')))
            ),
        ];
    }

    /**
     * Critical extensions the validator decodes but does not process.
     *
     * @return Iterator<string, array{Extension}>
     */
    public static function unprocessedCriticalExtensions(): Iterator
    {
        yield 'unknown' => [self::unknownExtension(true)];
        yield 'subjectAltName' => [
            SubjectAlternativeNameExtension::create(true, GeneralNames::create(DNSName::create('example.com'))),
        ];
        yield 'extendedKeyUsage' => [
            ExtendedKeyUsageExtension::create(true, ExtendedKeyUsageExtension::OID_CLIENT_AUTH),
        ];
    }

    #[Test]
    #[DataProvider('unprocessedCriticalExtensions')]
    public function unprocessedCriticalExtensionInEndEntityCertificateIsRejected(Extension $extension)
    {
        $path = self::createPath([], [$extension]);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('unhandled critical extension');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    #[DataProvider('unprocessedCriticalExtensions')]
    public function unprocessedCriticalExtensionInIssuerCertificateIsRejected(Extension $extension)
    {
        $path = self::createPath([$extension], []);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('unhandled critical extension');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    #[DataProvider('processedCriticalExtensions')]
    public function processedCriticalExtensionIsAccepted(Extension $extension)
    {
        $path = self::createPath([], [$extension]);
        $result = $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
        static::assertInstanceOf(PathValidationResult::class, $result);
    }

    #[Test]
    public function unknownNonCriticalExtensionIsAccepted()
    {
        $path = self::createPath([self::unknownExtension(false)], [self::unknownExtension(false)]);
        $result = $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
        static::assertInstanceOf(PathValidationResult::class, $result);
    }

    #[Test]
    public function unknownCriticalExtensionIsReportedByItsOID()
    {
        $path = self::createPath([], [self::unknownExtension(true)]);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage(self::UNKNOWN_OID);
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function criticalExtensionDeclaredInConfigurationIsAccepted()
    {
        $path = self::createPath([self::unknownExtension(true)], [self::unknownExtension(true)]);
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3)
            ->withAdditionalCriticalExtensions(self::UNKNOWN_OID);
        $result = $path->validate($config);
        static::assertInstanceOf(PathValidationResult::class, $result);
    }

    #[Test]
    public function criticalExtensionDeclaredInConfigurationDoesNotAcceptOtherExtensions()
    {
        $path = self::createPath([], [
            SubjectAlternativeNameExtension::create(true, GeneralNames::create(DNSName::create('example.com'))),
        ]);
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3)
            ->withAdditionalCriticalExtensions(self::UNKNOWN_OID);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('unhandled critical extension');
        $path->validate($config);
    }

    private static function unknownExtension(bool $critical): UnknownExtension
    {
        return UnknownExtension::create(self::UNKNOWN_OID, $critical, OctetString::create('hello'));
    }

    /**
     * Build a two certificate path with the given extra extensions.
     *
     * @param list<Extension> $caExtensions Extra extensions of the CA certificate
     * @param list<Extension> $certExtensions Extra extensions of the end-entity certificate
     */
    private static function createPath(array $caExtensions, array $certExtensions): CertificationPath
    {
        $tbs = TBSCertificate::create(
            Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withAdditionalExtensions(BasicConstraintsExtension::create(true, true, 1), ...$caExtensions);
        $ca = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
        $tbs = TBSCertificate::create(
            Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate($ca);
        if (count($certExtensions) !== 0) {
            $tbs = $tbs->withAdditionalExtensions(...$certExtensions);
        }
        $cert = $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_caKey);
        return CertificationPath::create($ca, $cert);
    }
}
