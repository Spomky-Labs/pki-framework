<?php

declare(strict_types=1);

namespace unit\rfc8410;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PrivateKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PublicKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PrivateKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PublicKey;

/**
 * @group rfc8410
 *
 * @internal
 */
class Curve25519Test extends TestCase
{
    public function testDecodeEd25519WithPub(): Ed25519PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        $this->assertInstanceOf(Ed25519PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testDecodeEd25519WithPub
     */
    public function testRecodeEd25519WithPub(Ed25519PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $this->assertEquals($pem->data(), $pk->toPEM()->data());
    }

    public function testDecodeEd25519(): Ed25519PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        $this->assertInstanceOf(Ed25519PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testDecodeEd25519
     */
    public function testRecodeEd25519(Ed25519PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $this->assertEquals($pem->data(), $pk->toPEM()->data());
    }

    /**
     * @depends testDecodeEd25519WithPub
     */
    public function testEd25519PrivateKeyData(Ed25519PrivateKey $pk)
    {
        /** @see https://datatracker.ietf.org/doc/html/rfc8410#section-10.3 */
        $data = <<<'DATA'
D4 EE 72 DB F9 13 58 4A D5 B6 D8 F1 F7 69 F8 AD
3A FE 7C 28 CB F1 D4 FB E0 97 A8 8F 44 75 58 42
DATA;
        $data = hex2bin(preg_replace('/[^\w]+/', '', $data));
        $this->assertEquals($data, $pk->privateKeyData());
    }

    /**
     * @depends testDecodeEd25519WithPub
     */
    public function testEd25519HasPublicKey(Ed25519PrivateKey $pk)
    {
        $this->assertTrue($pk->hasPublicKey());
    }

    /**
     * @depends testDecodeEd25519WithPub
     */
    public function testEd25519PublicKey(Ed25519PrivateKey $pk): Ed25519PublicKey
    {
        $pub = $pk->publicKey();
        $this->assertInstanceOf(Ed25519PublicKey::class, $pub);
        return $pub;
    }

    public function testEd25519PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        new Ed25519PrivateKey('');
    }

    public function testEd25519PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed25519PrivateKey(str_repeat("\0", 32), '');
    }

    public function testEd25519PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed25519PublicKey('');
    }

    public function testEd25519PkNoPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pk = Ed25519PrivateKey::fromPEM($pem);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    public function testEd25519PubKeyInfo()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    public function testEd25519PrivPubKeyData()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_public_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(BitString::class, $pki->publicKeyData());
    }

    public function testEd25519NoPrivPubKeyData()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/No explicit public key/');
        $pki->publicKeyData();
    }

    public function testDecodeEd25519Pub(): Ed25519PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(Ed25519PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends testDecodeEd25519Pub
     */
    public function testRecodeEd25519Pub(Ed25519PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_public_key.pem');
        $this->assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    /**
     * @depends testDecodeEd25519Pub
     */
    public function testEd25519PubNoDer(Ed25519PublicKey $pub)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/doesn\'t have a DER/');
        $pub->toDER();
    }

    /**
     * @depends testDecodeEd25519Pub
     */
    public function testEd25519PubKeyData(Ed25519PublicKey $pub)
    {
        $this->assertInstanceOf(BitString::class, $pub->subjectPublicKey());
    }

    public function testDecodeX25519(): X25519PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        $this->assertInstanceOf(X25519PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testDecodeX25519
     */
    public function testRecodeX25519(X25519PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_private_key.pem');
        $this->assertEquals($pem->data(), $pk->toPEM()->data());
    }

    public function testDecodeX25519Pub(): X25519PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(X25519PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends testDecodeX25519Pub
     */
    public function testRecodeX25519Pub(X25519PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_public_key.pem');
        $this->assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    public function testX25519PkNoPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x25519_private_key.pem');
        $pk = X25519PrivateKey::fromPEM($pem);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    public function testX25519PkGetPub()
    {
        $pk = new X25519PrivateKey(str_repeat("\0", 32), str_repeat("\0", 32));
        $this->assertInstanceOf(X25519PublicKey::class, $pk->publicKey());
    }
}
