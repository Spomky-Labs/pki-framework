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
    public function testDecodeEd448(): Ed448PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        $this->assertInstanceOf(Ed448PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testDecodeEd448
     */
    public function testRecodeEd448(Ed448PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        $this->assertEquals($pem->data(), $pk->toPEM()->data());
    }

    public function testDecodeEd448Pub(): Ed448PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(Ed448PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends testDecodeEd448Pub
     */
    public function testRecodeEd448Pub(Ed448PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_public_key.pem');
        $this->assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    public function testEd448PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        new Ed448PrivateKey('');
    }

    public function testEd448PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed448PrivateKey(str_repeat("\0", 57), '');
    }

    public function testEd448PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new Ed448PublicKey('');
    }

    public function testEd448PublicKey()
    {
        $pk = new Ed448PrivateKey(str_repeat("\0", 57), str_repeat("\0", 57));
        $this->assertInstanceOf(Ed448PublicKey::class, $pk->publicKey());
    }

    /**
     * @depends testDecodeEd448
     */
    public function testEd448PublicKeyNotSet(Ed448PrivateKey $pk)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }

    public function testDecodeX448(): X448PrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $pk = $pki->privateKey();
        $this->assertInstanceOf(X448PrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testDecodeX448
     */
    public function testRecodeX448(X448PrivateKey $pk)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_private_key.pem');
        $this->assertEquals($pem->data(), $pk->toPEM()->data());
    }

    public function testDecodeX448Pub(): X448PublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_public_key.pem');
        $pub = PublicKey::fromPEM($pem);
        $this->assertInstanceOf(X448PublicKey::class, $pub);
        return $pub;
    }

    /**
     * @depends testDecodeX448Pub
     */
    public function testRecodeX448Pub(X448PublicKey $pub)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/x448_public_key.pem');
        $this->assertEquals($pem->data(), $pub->publicKeyInfo()->toPEM()->data());
    }

    public function testX448PkInvalidPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/private key/');
        new X448PrivateKey('');
    }

    public function testX448PkInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new X448PrivateKey(str_repeat("\0", 56), '');
    }

    public function testX448PubInvalidPublicKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/public key/');
        new X448PublicKey('');
    }

    public function testX448PublicKey()
    {
        $pk = new X448PrivateKey(str_repeat("\0", 56), str_repeat("\0", 56));
        $this->assertInstanceOf(X448PublicKey::class, $pk->publicKey());
    }

    /**
     * @depends testDecodeX448
     */
    public function testX448PublicKeyNotSet(X448PrivateKey $pk)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pk->publicKey();
    }
}
