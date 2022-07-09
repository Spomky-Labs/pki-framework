<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RFC8410;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class Curve25519Test extends TestCase
{
    /**
     * @test
     */
    public function decodeEd25519WithPub(): Ed25519PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(Ed25519PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decodeEd25519WithPub
     *
     * @test
     */
    public function recodeEd25519WithPub(Ed25519PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        static::assertEquals($pem->data(), $pk->toPEM()->data());
    }

    /**
     * @test
     */
    public function decodeEd25519(): Ed25519PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(Ed25519PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decodeEd25519
     *
     * @test
     */
    public function recodeEd25519(Ed25519PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        static::assertEquals($pem->data(), $pk->toPEM()->data());
    }

    /**
     * @depends decodeEd25519WithPub
     *
     * @test
     */
    public function ed25519PrivateKeyData(Ed25519PrivateKey $pk)
    {
        /** @see https://datatracker.ietf.org/doc/html/rfc8410#section-10.3 */
        $data = <<<'CODE_SAMPLE'
D4 EE 72 DB F9 13 58 4A D5 B6 D8 F1 F7 69 F8 AD
3A FE 7C 28 CB F1 D4 FB E0 97 A8 8F 44 75 58 42
CODE_SAMPLE;
        $data = hex2bin(preg_replace('/[^\w]+/', '', $data));
        static::assertEquals($data, $pk->privateKeyData());
    }

    /**
     * @depends decodeEd25519WithPub
     *
     * @test
     */
    public function ed25519HasPublicKey(Ed25519PrivateKey $pk)
    {
        static::assertTrue($pk->hasPublicKey());
    }

    /**
     * @depends decodeEd25519WithPub
     *
     * @test
     */
    public function ed25519PublicKey(Ed25519PrivateKey $pk): Ed25519PublicKey
    {
        $pub = $pk->publicKey();
        static::assertInstanceOf(Ed25519PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @test
     */
    public function ed25519PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        new Ed25519PrivateKey('');
    }

    /**
     * @test
     */
    public function ed25519PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed25519PrivateKey(str_repeat("\0", 32), '');
    }

    /**
     * @test
     */
    public function ed25519PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed25519PublicKey('');
    }

    /**
     * @test
     */
    public function ed25519PkNoPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pk = Ed25519PrivateKey::fromPEM($pem);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    /**
     * @test
     */
    public function ed25519PubKeyInfo()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @test
     */
    public function ed25519PrivPubKeyData()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(BitString::class, $pki->publicKeyData());
    }

    /**
     * @test
     */
    public function ed25519NoPrivPubKeyData()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/No explicit public key/');
        $pki->publicKeyData();
    }

    /**
     * @test
     */
    public function decodeEd25519Pub(): Ed25519PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        static::assertInstanceOf(Ed25519PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends decodeEd25519Pub
     *
     * @test
     */
    public function recodeEd25519Pub(Ed25519PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_public_key.pem');
        static::assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    /**
     * @depends decodeEd25519Pub
     *
     * @test
     */
    public function ed25519PubNoDer(Ed25519PublicKey $pub)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/doesn\'t have a DER/');
        $pub->toDER();
    }

    /**
     * @depends decodeEd25519Pub
     *
     * @test
     */
    public function ed25519PubKeyData(Ed25519PublicKey $pub)
    {
        static::assertInstanceOf(BitString::class, $pub->subjectPublicKey());
    }

    /**
     * @test
     */
    public function decodeX25519(): X25519PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        static::assertInstanceOf(X25519PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decodeX25519
     *
     * @test
     */
    public function recodeX25519(X25519PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_private_key.pem');
        static::assertEquals($pem->data(), $pk->toPEM()->data());
    }

    /**
     * @test
     */
    public function decodeX25519Pub(): X25519PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        static::assertInstanceOf(X25519PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends decodeX25519Pub
     *
     * @test
     */
    public function recodeX25519Pub(X25519PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_public_key.pem');
        static::assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    /**
     * @test
     */
    public function x25519PkNoPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_private_key.pem');
        $pk = X25519PrivateKey::fromPEM($pem);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    /**
     * @test
     */
    public function x25519PkGetPub()
    {
        $pk = new X25519PrivateKey(str_repeat("\0", 32), str_repeat("\0", 32));
        static::assertInstanceOf(X25519PublicKey::class, $pk->publicKey());
    }
}
