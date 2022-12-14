<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class RSAPublicKeyTest extends TestCase
{
    /**
     * @return RSAPublicKey
     *
     * @test
     */
    public function decode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = RSAPublicKey::fromDER($pem->data());
        static::assertInstanceOf(RSAPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @return RSAPublicKey
     *
     * @test
     */
    public function fromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function toPEM(RSAPublicKey $pk)
    {
        $pem = $pk->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        static::assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        RSAPublicKey::fromPEM($pem);
    }

    /**
     * @test
     */
    public function eCKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $this->expectException(UnexpectedValueException::class);
        RSAPublicKey::fromPEM($pem);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function modulus(RSAPublicKey $pk)
    {
        static::assertNotEmpty($pk->modulus());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function publicExponent(RSAPublicKey $pk)
    {
        static::assertNotEmpty($pk->publicExponent());
    }
}
