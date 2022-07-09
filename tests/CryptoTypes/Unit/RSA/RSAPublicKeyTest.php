<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
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
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
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
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
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
        $this->assertInstanceOf(PEM::class, $pem);
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
        $this->assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
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
        $this->assertNotEmpty($pk->modulus());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function publicExponent(RSAPublicKey $pk)
    {
        $this->assertNotEmpty($pk->publicExponent());
    }
}
