<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\RFC8410;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PrivateKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PublicKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PrivateKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class Curve448Test extends TestCase
{
    /**
     * @test
     */
    public function decodeEd448(): Ed448PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(Ed448PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decodeEd448
     *
     * @test
     */
    public function recodeEd448(Ed448PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        static::assertEquals($pem->data(), $pk->toPEM()->data());
    }

    /**
     * @test
     */
    public function decodeEd448Pub(): Ed448PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        static::assertInstanceOf(Ed448PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends decodeEd448Pub
     *
     * @test
     */
    public function recodeEd448Pub(Ed448PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_public_key.pem');
        static::assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    /**
     * @test
     */
    public function ed448PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        new Ed448PrivateKey('');
    }

    /**
     * @test
     */
    public function ed448PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed448PrivateKey(str_repeat("\0", 57), '');
    }

    /**
     * @test
     */
    public function ed448PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed448PublicKey('');
    }

    /**
     * @test
     */
    public function ed448PublicKey()
    {
        $pk = new Ed448PrivateKey(str_repeat("\0", 57), str_repeat("\0", 57));
        static::assertInstanceOf(Ed448PublicKey::class, $pk->publicKey());
    }

    /**
     * @depends decodeEd448
     *
     * @test
     */
    public function ed448PublicKeyNotSet(Ed448PrivateKey $pk)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    /**
     * @test
     */
    public function decodeX448(): X448PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(X448PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decodeX448
     *
     * @test
     */
    public function recodeX448(X448PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_private_key.pem');
        static::assertEquals($pem->data(), $pk->toPEM()->data());
    }

    /**
     * @test
     */
    public function decodeX448Pub(): X448PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        static::assertInstanceOf(X448PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends decodeX448Pub
     *
     * @test
     */
    public function recodeX448Pub(X448PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_public_key.pem');
        static::assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    /**
     * @test
     */
    public function x448PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        new X448PrivateKey('');
    }

    /**
     * @test
     */
    public function x448PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new X448PrivateKey(str_repeat("\0", 56), '');
    }

    /**
     * @test
     */
    public function x448PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new X448PublicKey('');
    }

    /**
     * @test
     */
    public function x448PublicKey()
    {
        $pk = new X448PrivateKey(str_repeat("\0", 56), str_repeat("\0", 56));
        static::assertInstanceOf(X448PublicKey::class, $pk->publicKey());
    }

    /**
     * @depends decodeX448
     *
     * @test
     */
    public function x448PublicKeyNotSet(X448PrivateKey $pk)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }
}
