<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;

/**
 * @internal
 */
final class RSAPublicKeyTest extends TestCase
{
    /**
     * @return RSAPublicKey
     */
    public function testDecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = RSAPublicKey::fromDER($pem->data());
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @return RSAPublicKey
     */
    public function testFromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testFromPEM
     */
    public function testToPEM(RSAPublicKey $pk)
    {
        $pem = $pk->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     */
    public function testRecodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $this->assertEquals($ref, $pem);
    }

    public function testFromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pk = RSAPublicKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        RSAPublicKey::fromPEM($pem);
    }

    public function testECKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $this->expectException(\UnexpectedValueException::class);
        RSAPublicKey::fromPEM($pem);
    }

    /**
     * @depends testDecode
     */
    public function testModulus(RSAPublicKey $pk)
    {
        $this->assertNotEmpty($pk->modulus());
    }

    /**
     * @depends testDecode
     */
    public function testPublicExponent(RSAPublicKey $pk)
    {
        $this->assertNotEmpty($pk->publicExponent());
    }
}
