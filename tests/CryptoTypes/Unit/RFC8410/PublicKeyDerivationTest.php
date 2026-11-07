<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RFC8410;

use function dirname;
use function extension_loaded;
use function function_exists;
use Iterator;
use LogicException;
use const OPENSSL_VERSION_TEXT;
use const PHP_BINARY;
use const PHP_VERSION;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed25519AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\X25519AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\X448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\PublicKeyDerivation;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\RFC8410PrivateKey;
use function sprintf;

/**
 * Deriving the public key of an RFC 8410 private key that does not embed it.
 *
 * OpenSSL leaves the public key out of the PKCS #8 structures it writes, so without derivation `publicKey()` failed
 * for virtually every Ed25519 and Ed448 key in the wild.
 *
 * @internal
 */
final class PublicKeyDerivationTest extends TestCase
{
    /**
     * Test vectors from RFC 8032 (Ed25519, Ed448) and RFC 7748 (X25519, X448): private key, public key.
     *
     * @return Iterator<string, array{RFC8410PrivateKey, string}>
     */
    public static function vectorProvider(): Iterator
    {
        // RFC 8032 section 7.1, TEST 1
        yield 'Ed25519 RFC 8032 TEST 1' => [
            Ed25519PrivateKey::create(
                self::hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
            ),
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        ];
        // RFC 7748 section 6.1
        yield 'X25519 RFC 7748 Alice' => [
            X25519PrivateKey::create(
                self::hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
            ),
            '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
        ];
        yield 'X25519 RFC 7748 Bob' => [
            X25519PrivateKey::create(
                self::hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
            ),
            'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        ];
        // RFC 8032 section 7.4, -----Blank
        yield 'Ed448 RFC 8032 Blank' => [
            Ed448PrivateKey::create(self::hex(
                '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3' .
                '528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b'
            )),
            '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778' .
            'edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
        ];
        // RFC 8032 section 7.4, 1 octet
        yield 'Ed448 RFC 8032 1 octet' => [
            Ed448PrivateKey::create(self::hex(
                'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a' .
                'fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e'
            )),
            '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086' .
            '6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
        ];
        // RFC 7748 section 6.2
        yield 'X448 RFC 7748 Alice' => [
            X448PrivateKey::create(self::hex(
                '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5' .
                '74a9419744897391006382a6f127ab1d9ac2d8c0a598726b'
            )),
            '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb' .
            'c836647241d953d40c5b12da88120d53177f80e532c41fa0',
        ];
        yield 'X448 RFC 7748 Bob' => [
            X448PrivateKey::create(self::hex(
                '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120' .
                'bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d'
            )),
            '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972' .
            'fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609',
        ];
    }

    /**
     * @return Iterator<string, array{string}>
     */
    public static function assetProvider(): Iterator
    {
        yield 'Ed25519' => ['ed25519'];
        yield 'X25519' => ['x25519'];
        yield 'Ed448' => ['ed448'];
        yield 'X448' => ['x448'];
    }

    /**
     * @return Iterator<string, array{AlgorithmIdentifierType}>
     */
    public static function algorithmProvider(): Iterator
    {
        yield 'Ed25519' => [Ed25519AlgorithmIdentifier::create()];
        yield 'X25519' => [X25519AlgorithmIdentifier::create()];
        yield 'Ed448' => [Ed448AlgorithmIdentifier::create()];
        yield 'X448' => [X448AlgorithmIdentifier::create()];
    }

    #[Test]
    #[DataProvider('vectorProvider')]
    public function thePublicKeyIsDerivedFromTheVector(RFC8410PrivateKey $key, string $expected): void
    {
        self::requireDerivation($key->algorithmIdentifier());

        static::assertFalse($key->hasPublicKey());
        static::assertSame(
            $expected,
            bin2hex($key->publicKey()->subjectPublicKey()->string())
        );
    }

    #[Test]
    #[DataProvider('vectorProvider')]
    public function sodiumDerivesCurve25519Keys(RFC8410PrivateKey $key, string $expected): void
    {
        $derived = PublicKeyDerivation::viaSodium($key->algorithmIdentifier(), $key->privateKeyData());
        if (! $key instanceof Ed25519PrivateKey && ! $key instanceof X25519PrivateKey) {
            static::assertNull($derived, 'ext-sodium has no Curve448.');
            return;
        }
        if (! extension_loaded('sodium')) {
            static::markTestSkipped('ext-sodium is not available.');
        }

        static::assertSame($expected, bin2hex((string) $derived));
    }

    #[Test]
    #[DataProvider('vectorProvider')]
    public function openSSLDerivesEveryAlgorithm(RFC8410PrivateKey $key, string $expected): void
    {
        // This is the path Ed25519 and X25519 fall back to without ext-sodium
        if (! PublicKeyDerivation::opensslSupports($key->algorithmIdentifier())) {
            static::markTestSkipped(sprintf(
                'The OpenSSL extension of this runtime (%s) cannot derive %s public keys.',
                OPENSSL_VERSION_TEXT,
                $key->algorithmIdentifier()
                    ->name()
            ));
        }

        static::assertSame(
            $expected,
            bin2hex((string) PublicKeyDerivation::viaOpenSSL($key->algorithmIdentifier(), $key->privateKeyData()))
        );
    }

    #[Test]
    #[DataProvider('algorithmProvider')]
    public function openSSLSupportIsProbedConsistently(AlgorithmIdentifierType $algo): void
    {
        $supported = PublicKeyDerivation::opensslSupports($algo);

        static::assertSame($supported, PublicKeyDerivation::opensslSupports($algo));
        static::assertSame($supported, PublicKeyDerivation::viaOpenSSL($algo, self::dummyKey($algo)) !== null);
    }

    #[Test]
    #[DataProvider('assetProvider')]
    public function thePublicKeyOfAKeyGeneratedByOpenSSLIsDerived(string $algorithm): void
    {
        $pki = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_private_key.pem"));
        $key = $pki->privateKey();
        static::assertInstanceOf(RFC8410PrivateKey::class, $key);
        self::requireDerivation($key->algorithmIdentifier());
        $expected = PEM::fromFile(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_public_key.pem")->data();

        static::assertFalse($pki->hasPublicKeyData());
        static::assertFalse($key->hasPublicKey());
        static::assertSame($expected, $pki->publicKeyInfo()->toDER());
        static::assertSame($expected, $key->publicKey()->publicKeyInfo()->toDER());
    }

    #[Test]
    #[DataProvider('assetProvider')]
    public function derivingThePublicKeyDoesNotChangeTheEncoding(string $algorithm): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_private_key.pem");
        $key = PrivateKeyInfo::fromPEM($pem)->privateKey();
        static::assertInstanceOf(RFC8410PrivateKey::class, $key);
        self::requireDerivation($key->algorithmIdentifier());

        $public = $key->publicKey();

        static::assertFalse($key->hasPublicKey());
        static::assertSame($pem->data(), $key->toPEM()->data());
        static::assertEquals($public, $key->publicKey());
        // The derived key survives the with*() clones, which keep the private key as it is
        static::assertEquals($public, $key->withVersion(OneAsymmetricKey::VERSION_2)->publicKey());
        static::assertSame(
            $pem->data(),
            $key->withVersion(OneAsymmetricKey::VERSION_2)
                ->withVersion(OneAsymmetricKey::VERSION_1)
                ->toPEM()
                ->data()
        );
    }

    #[Test]
    public function anEmbeddedPublicKeyWinsOverTheDerivedOne(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $key = PrivateKeyInfo::fromPEM($pem)->privateKey();
        static::assertInstanceOf(Ed25519PrivateKey::class, $key);
        static::assertTrue($key->hasPublicKey());
        $embedded = $key->publicKey()
            ->subjectPublicKey()
            ->string();

        // Embedding a key that does not belong to the private key is the caller's business: it is used as is.
        $mismatched = Ed25519PrivateKey::create($key->privateKeyData(), str_repeat("\x01", 32));

        static::assertSame(
            str_repeat("\x01", 32),
            $mismatched->publicKey()
                ->subjectPublicKey()
                ->string()
        );
        static::assertSame(
            $embedded,
            Ed25519PrivateKey::create($key->privateKeyData())->publicKey()
                ->subjectPublicKey()
                ->string()
        );
    }

    #[Test]
    public function sodiumIsNotHandedAKeyOfTheWrongSize(): void
    {
        // ext-sodium throws on these rather than failing softly
        foreach ([Ed25519AlgorithmIdentifier::create(), X25519AlgorithmIdentifier::create()] as $algo) {
            static::assertNull(PublicKeyDerivation::viaSodium($algo, str_repeat("\x01", 31)));
            static::assertNull(PublicKeyDerivation::viaSodium($algo, str_repeat("\x01", 33)));
        }
    }

    #[Test]
    public function anAlgorithmWithoutDerivationIsRefusedWithAReason(): void
    {
        $algo = RSAEncryptionAlgorithmIdentifier::create();

        static::assertNull(PublicKeyDerivation::viaSodium($algo, str_repeat("\0", 32)));
        static::assertFalse(PublicKeyDerivation::opensslSupports($algo));
        static::assertNull(PublicKeyDerivation::viaOpenSSL($algo, str_repeat("\0", 32)));
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            'Public key not set and this PHP runtime cannot derive it from the rsaEncryption private key: ' .
            'that needs ext-sodium (Ed25519 and X25519 only) or an OpenSSL extension supporting the algorithm.'
        );

        PublicKeyDerivation::derive($algo, str_repeat("\0", 32));
    }

    /**
     * The fallbacks, exercised in a PHP process with the functions they would use disabled.
     *
     * ext-sodium is only suggested, and the OpenSSL extension may lack the algorithm. Disabling functions is the
     * one way to take them away from a single process without a test seam in the library.
     *
     * @return Iterator<string, array{string, string, string}>
     */
    public static function fallbackProvider(): Iterator
    {
        $sodium = 'sodium_crypto_sign_seed_keypair,sodium_crypto_scalarmult_base';
        foreach (['ed25519', 'x25519'] as $algorithm) {
            yield "{$algorithm} without ext-sodium falls back to OpenSSL" => [$algorithm, $sodium, 'openssl'];
            yield "{$algorithm} without OpenSSL uses ext-sodium" => [$algorithm, 'openssl_pkey_get_private', 'sodium'];
            yield "{$algorithm} without either fails" => [$algorithm, $sodium . ',openssl_pkey_get_private', 'none'];
        }
        foreach (['ed448', 'x448'] as $algorithm) {
            yield "{$algorithm} without OpenSSL fails" => [$algorithm, 'openssl_pkey_get_private', 'none'];
        }
    }

    #[Test]
    #[DataProvider('fallbackProvider')]
    public function theFallbacksWork(string $algorithm, string $disabled, string $engine): void
    {
        if (! function_exists('proc_open')) {
            static::markTestSkipped('proc_open() is not available.');
        }
        if ($engine === 'sodium' && ! extension_loaded('sodium')) {
            static::markTestSkipped('ext-sodium is not available.');
        }
        $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_private_key.pem"))
            ->privateKey();
        if ($engine === 'openssl' && ! PublicKeyDerivation::opensslSupports($key->algorithmIdentifier())) {
            static::markTestSkipped(sprintf(
                'The OpenSSL extension of this runtime (%s) cannot derive %s public keys.',
                OPENSSL_VERSION_TEXT,
                $key->algorithmIdentifier()
                    ->name()
            ));
        }

        $code = <<<'PHP'
            require $argv[1];
            try {
                echo \SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo::fromPEM(
                    \SpomkyLabs\Pki\CryptoEncoding\PEM::fromFile($argv[2])
                )->publicKeyInfo()->toPEM();
            } catch (\LogicException $e) {
                echo get_class($e), ': ', $e->getMessage();
            }
            PHP;
        $process = proc_open(
            [
                PHP_BINARY,
                '-d',
                'disable_functions=' . $disabled,
                '-d',
                'display_errors=stderr',
                '-r',
                $code,
                '--',
                dirname(__DIR__, 4) . '/vendor/autoload.php',
                TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_private_key.pem",
            ],
            [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes
        );
        static::assertIsResource($process);
        $output = (string) stream_get_contents($pipes[1]);
        $errors = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        static::assertSame(0, proc_close($process), $errors);

        if ($engine === 'none') {
            static::assertStringStartsWith('LogicException: Public key not set and this PHP runtime cannot', $output);
            return;
        }
        static::assertSame(
            trim((string) file_get_contents(TEST_ASSETS_DIR . "/rfc8410/{$algorithm}_public_key.pem")),
            $output
        );
    }

    private static function requireDerivation(AlgorithmIdentifierType $algo): void
    {
        if (PublicKeyDerivation::viaSodium($algo, self::dummyKey($algo)) === null
            && ! PublicKeyDerivation::opensslSupports($algo)) {
            static::markTestSkipped(sprintf(
                'This runtime (PHP %s, %s) cannot derive %s public keys.',
                PHP_VERSION,
                OPENSSL_VERSION_TEXT,
                $algo->name()
            ));
        }
    }

    private static function dummyKey(AlgorithmIdentifierType $algo): string
    {
        return str_repeat("\x01", match ($algo->name()) {
            'id-Ed448' => 57,
            'id-X448' => 56,
            default => 32,
        });
    }

    private static function hex(string $hex): string
    {
        return (string) hex2bin($hex);
    }
}
