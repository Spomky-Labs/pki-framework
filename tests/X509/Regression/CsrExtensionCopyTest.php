<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use function sprintf;

/**
 * The extensions a certification request asks for are written by the requester. Copying them wholesale, as the
 * only documented issuance path did, handed out an intermediate CA to anyone who asked for one.
 *
 * @internal
 */
final class CsrExtensionCopyTest extends TestCase
{
    private static ?PrivateKeyInfo $key = null;

    public static function setUpBeforeClass(): void
    {
        self::$key = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))
            ->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$key = null;
    }

    #[Test]
    public function privilegedExtensionsAreNeverCopied(): void
    {
        $tbs = TBSCertificate::fromCSR(self::hostileCsr());

        static::assertFalse($tbs->extensions()->hasBasicConstraints());
        static::assertFalse($tbs->extensions()->hasKeyUsage());
    }

    #[Test]
    public function ordinaryExtensionsAreStillCopied(): void
    {
        // Issuers that relied on subjectAltName being carried over keep working unchanged.
        $tbs = TBSCertificate::fromCSR(self::hostileCsr());

        static::assertTrue($tbs->extensions()->hasSubjectAlternativeName());
        static::assertSame(
            '*.example.org',
            $tbs->extensions()
                ->subjectAlternativeName()
                ->names()
                ->firstDNS()
        );
        static::assertTrue($tbs->extensions()->hasSubjectKeyIdentifier());
    }

    #[Test]
    public function theSetCanBeNarrowedFurther(): void
    {
        $tbs = TBSCertificate::fromCSR(self::hostileCsr(), [Extension::OID_ISSUER_ALT_NAME]);

        static::assertFalse($tbs->extensions()->hasSubjectAlternativeName());
        static::assertFalse($tbs->extensions()->hasBasicConstraints());
    }

    #[Test]
    public function anEmptyAllowListCopiesNothing(): void
    {
        $tbs = TBSCertificate::fromCSR(self::hostileCsr(), []);

        static::assertCount(1, $tbs->extensions());
        static::assertTrue($tbs->extensions()->hasSubjectKeyIdentifier());
    }

    #[Test]
    public function allowingAPrivilegedExtensionIsRefused(): void
    {
        // Refused rather than quietly ignored, so a mistaken allow-list shows up at the call site.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('cannot be taken from a certification request');
        TBSCertificate::fromCSR(self::hostileCsr(), [Extension::OID_BASIC_CONSTRAINTS]);
    }

    #[Test]
    public function everyPrivilegedExtensionIsRefused(): void
    {
        foreach (TBSCertificate::FORBIDDEN_CSR_EXTENSIONS as $oid) {
            try {
                TBSCertificate::fromCSR(self::hostileCsr(), [$oid]);
                static::fail(sprintf('Expected %s to be refused.', $oid));
            } catch (InvalidArgumentException) {
                static::assertTrue(true);
            }
        }
    }

    /**
     * @return iterable<array{string}>
     */
    public static function privilegedExtensionOids(): iterable
    {
        foreach (TBSCertificate::FORBIDDEN_CSR_EXTENSIONS as $oid) {
            yield $oid => [$oid];
        }
    }

    #[Test]
    #[DataProvider('privilegedExtensionOids')]
    public function everyPrivilegedExtensionIsDropped(string $oid): void
    {
        // Refusing them in the allow-list is not enough: a request asking for one directly must not get it either.
        $csr = self::csrRequesting(UnknownExtension::create($oid, true, NullType::create()));

        static::assertFalse(
            TBSCertificate::fromCSR($csr)->extensions()
                ->has($oid)
        );
    }

    private static function csrRequesting(Extension ...$extensions): CertificationRequest
    {
        $cri = CertificationRequestInfo::create(
            Name::fromString('cn=innocent-looking-client'),
            self::$key->publicKeyInfo()
        )->withExtensionRequest(Extensions::create(...$extensions));

        return $cri->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key);
    }

    private static function hostileCsr(): CertificationRequest
    {
        $extensions = Extensions::create(
            BasicConstraintsExtension::create(true, true),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN | KeyUsageExtension::CRL_SIGN),
            SubjectAlternativeNameExtension::create(false, GeneralNames::create(DNSName::create('*.example.org'))),
        );

        $cri = CertificationRequestInfo::create(
            Name::fromString('cn=innocent-looking-client'),
            self::$key->publicKeyInfo()
        )->withExtensionRequest($extensions);

        return $cri->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key);
    }
}
