<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Workflow;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoBridge\Crypto\OpenSSLCrypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed25519AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;
use function sprintf;
use UnexpectedValueException;

/**
 * Certificates and requests built from an EdDSA key as OpenSSL writes it, without the public key embedded.
 *
 * @internal
 */
final class RFC8410DerivedPublicKeyTest extends TestCase
{
    /**
     * @return Iterator<string, array{string, SignatureAlgorithmIdentifier}>
     */
    public static function keyProvider(): Iterator
    {
        yield 'Ed25519' => ['ed25519', Ed25519AlgorithmIdentifier::create()];
        yield 'Ed448' => ['ed448', Ed448AlgorithmIdentifier::create()];
    }

    #[Test]
    #[DataProvider('keyProvider')]
    public function aSelfSignedCertificateVerifies(string $algorithm, SignatureAlgorithmIdentifier $algo): void
    {
        $key = self::privateKey($algorithm);
        $subject = Name::fromString('cn=RFC 8410');
        $tbs = TBSCertificate::create(
            $subject,
            $key->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        )->withSerialNumber('1');
        static::assertSame(
            self::publicKeyDER($algorithm),
            $tbs->subjectPublicKeyInfo()
                ->toDER()
        );

        try {
            $cert = $tbs->sign($algo, $key);
        } catch (UnexpectedValueException $e) {
            static::markTestSkipped($e->getMessage());
        }

        self::requireVerification($algo);
        static::assertTrue($cert->verify($key->publicKeyInfo()));
    }

    #[Test]
    #[DataProvider('keyProvider')]
    public function aCertificationRequestVerifies(string $algorithm, SignatureAlgorithmIdentifier $algo): void
    {
        $key = self::privateKey($algorithm);
        $cri = CertificationRequestInfo::create(Name::fromString('cn=RFC 8410'), $key->publicKeyInfo());
        static::assertSame(
            self::publicKeyDER($algorithm),
            $cri->subjectPKInfo()
                ->toDER()
        );

        try {
            $csr = $cri->sign($algo, $key);
        } catch (UnexpectedValueException $e) {
            static::markTestSkipped($e->getMessage());
        }

        self::requireVerification($algo);
        static::assertTrue($csr->verify());
    }

    private static function privateKey(string $algorithm): PrivateKeyInfo
    {
        $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_private_key.pem"));
        static::assertFalse($key->hasPublicKeyData());
        return $key;
    }

    private static function publicKeyDER(string $algorithm): string
    {
        return PEM::fromFile(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_public_key.pem")->data();
    }

    private static function requireVerification(SignatureAlgorithmIdentifier $algo): void
    {
        if (! (new OpenSSLCrypto())->supportsSignatureAlgorithm($algo)) {
            static::markTestSkipped(sprintf('This runtime cannot verify %s.', $algo->name()));
        }
    }
}
