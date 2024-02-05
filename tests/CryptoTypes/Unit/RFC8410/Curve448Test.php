<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RFC8410;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class Curve448Test extends TestCase
{
    #[Test]
    public function decodeEd448(): Ed448PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(Ed448PrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('decodeEd448')]
    public function recodeEd448(Ed448PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        static::assertSame($pem->data(), $pk->toPEM()->data());
    }

    #[Test]
    public function decodeEd448Pub(): Ed448PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        static::assertInstanceOf(Ed448PublicKey::class, $pub);
        return $pub;
    }

    #[Test]
    #[Depends('decodeEd448Pub')]
    public function recodeEd448Pub(Ed448PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_public_key.pem');
        static::assertSame($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    #[Test]
    public function ed448PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        Ed448PrivateKey::create('');
    }

    #[Test]
    public function ed448PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        Ed448PrivateKey::create(str_repeat("\0", 57), '');
    }

    #[Test]
    public function ed448PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        Ed448PublicKey::create('');
    }

    #[Test]
    public function ed448PublicKey()
    {
        $pk = Ed448PrivateKey::create(str_repeat("\0", 57), str_repeat("\0", 57));
        static::assertInstanceOf(Ed448PublicKey::class, $pk->publicKey());
    }

    #[Test]
    #[Depends('decodeEd448')]
    public function ed448PublicKeyNotSet(Ed448PrivateKey $pk)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    #[Test]
    public function decodeX448(): X448PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(X448PrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('decodeX448')]
    public function recodeX448(X448PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_private_key.pem');
        static::assertSame($pem->data(), $pk->toPEM()->data());
    }

    #[Test]
    public function decodeX448Pub(): X448PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        static::assertInstanceOf(X448PublicKey::class, $pub);
        return $pub;
    }

    #[Test]
    #[Depends('decodeX448Pub')]
    public function recodeX448Pub(X448PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_public_key.pem');
        static::assertSame($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    #[Test]
    public function x448PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        X448PrivateKey::create('');
    }

    #[Test]
    public function x448PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        X448PrivateKey::create(str_repeat("\0", 56), '');
    }

    #[Test]
    public function x448PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        X448PublicKey::create('');
    }

    #[Test]
    public function x448PublicKey()
    {
        $pk = X448PrivateKey::create(str_repeat("\0", 56), str_repeat("\0", 56));
        static::assertInstanceOf(X448PublicKey::class, $pk->publicKey());
    }

    #[Test]
    #[Depends('decodeX448')]
    public function x448PublicKeyNotSet(X448PrivateKey $pk)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }
}
