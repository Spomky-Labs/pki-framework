<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use function sprintf;

/**
 * Ed25519 and Ed448 were in the default allowed signature algorithms but could not be verified.
 *
 * OpenSSLCrypto::MAP_DIGEST_OID had an entry for neither, so a chain OpenSSL validates could not be validated at
 * all while the configuration advertised the capability. EdDSA is a one shot scheme: the message is not
 * pre-hashed, and openssl_verify() takes 0 as the digest method.
 *
 * @internal
 */
final class EdDSASignatureTest extends TestCase
{
    /**
     * @return Iterator<string, array{string}>
     */
    public static function edDSAAlgorithmProvider(): Iterator
    {
        yield 'Ed25519' => ['ed25519'];
        yield 'Ed448' => ['ed448'];
    }

    #[Test]
    #[DataProvider('edDSAAlgorithmProvider')]
    public function anEdDSACertificateVerifies(string $algorithm): void
    {
        $cert = self::selfSignedCertificate($algorithm);
        $key = $cert->tbsCertificate()
            ->subjectPublicKeyInfo();

        static::assertTrue($cert->verify($key));
    }

    #[Test]
    #[DataProvider('edDSAAlgorithmProvider')]
    public function anEdDSAChainValidates(string $algorithm): void
    {
        $cert = self::selfSignedCertificate($algorithm);

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($cert)
                ->validate(PathValidationConfig::defaultConfig()->withTrustAnchor($cert))
        );
    }

    #[Test]
    #[DataProvider('edDSAAlgorithmProvider')]
    public function aTamperedEdDSACertificateDoesNotVerify(string $algorithm): void
    {
        $cert = self::selfSignedCertificate($algorithm);
        $other = self::selfSignedCertificate($algorithm);

        static::assertFalse(
            $cert->verify(
                $other->tbsCertificate()
                    ->subjectPublicKeyInfo()
            )
        );
    }

    #[Test]
    public function verifyReturnsFalseRatherThanThrowingOnAnAlgorithmTheEngineCannotHandle(): void
    {
        // The algorithm is named by the certificate, so an attacker picks it. A bool returning predicate must
        // not turn `if (! $cert->verify($key))` into an unhandled fatal.
        $key = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))
            ->privateKeyInfo();
        $cert = self::rsaCertificate($key);

        static::assertFalse(
            $cert->verify(
                PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'))
                    ->privateKeyInfo()
                    ->publicKeyInfo()
            )
        );
    }

    #[Test]
    public function rsassaPssIsNoLongerAdvertisedWhileItIsNotImplemented(): void
    {
        // A PSS signed certificate is refused when it is parsed, so the entry was dead configuration.
        static::assertNotContains(
            AlgorithmIdentifier::OID_RSASSA_PSS_ENCRYPTION,
            PathValidationConfig::DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS
        );
        static::assertNotContains(
            AlgorithmIdentifier::OID_RSASSA_PSS_ENCRYPTION,
            PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS
        );
    }

    #[Test]
    public function edDSAIsStillInTheDefaultSet(): void
    {
        static::assertContains(
            AlgorithmIdentifier::OID_ED25519,
            PathValidationConfig::DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS
        );
        static::assertContains(
            AlgorithmIdentifier::OID_ED448,
            PathValidationConfig::DEFAULT_ALLOWED_SIGNATURE_ALGORITHMS
        );
    }

    private static function rsaCertificate(PrivateKeyInfo $key): Certificate
    {
        $subject = Name::fromString('cn=Test Root');

        return TBSCertificate::create(
            $subject,
            $key->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        )
            ->withSerialNumber('1')
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $key);
    }

    /**
     * OpenSSL is the only EdDSA implementation available here, so the fixture is generated rather than shipped.
     */
    private static function selfSignedCertificate(string $algorithm): Certificate
    {
        $dir = sys_get_temp_dir() . '/pki-eddsa-' . bin2hex(random_bytes(8));
        mkdir($dir);

        try {
            exec(sprintf(
                'openssl genpkey -algorithm %s -out %s/key.pem 2>/dev/null',
                escapeshellarg($algorithm),
                escapeshellarg($dir)
            ));
            exec(sprintf(
                'openssl req -new -x509 -key %s/key.pem -subj /CN=eddsa -days 3650 -out %s/cert.pem 2>/dev/null',
                escapeshellarg($dir),
                escapeshellarg($dir)
            ));

            if (! file_exists($dir . '/cert.pem')) {
                static::markTestSkipped(sprintf('The available OpenSSL cannot generate an %s key.', $algorithm));
            }

            return Certificate::fromPEM(PEM::fromFile($dir . '/cert.pem'));
        } finally {
            array_map(unlink(...), glob($dir . '/*') ?: []);
            rmdir($dir);
        }
    }
}
