<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class RSAPublicKeyTest extends TestCase
{
    #[Test]
    public function decode(): RSAPublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = RSAPublicKey::fromDER($pem->data());
        static::assertInstanceOf(RSAPublicKey::class, $pk);
        return $pk;
    }

    #[Test]
    public function fromPEM(): RSAPublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromPEM')]
    public function toPEM(RSAPublicKey $pk): PEM
    {
        $pem = $pk->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        static::assertEquals($ref, $pem);
    }

    #[Test]
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    #[Test]
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        RSAPublicKey::fromPEM($pem);
    }

    #[Test]
    public function eCKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $this->expectException(UnexpectedValueException::class);
        RSAPublicKey::fromPEM($pem);
    }

    #[Test]
    #[Depends('decode')]
    public function modulus(RSAPublicKey $pk)
    {
        static::assertNotEmpty($pk->modulus());
    }

    #[Test]
    #[Depends('decode')]
    public function publicExponent(RSAPublicKey $pk)
    {
        static::assertNotEmpty($pk->publicExponent());
    }
}
