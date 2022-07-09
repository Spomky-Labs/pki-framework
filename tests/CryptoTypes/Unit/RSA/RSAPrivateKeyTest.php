<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class RSAPrivateKeyTest extends TestCase
{
    /**
     * @return RSAPrivateKey
     *
     * @test
     */
    public function decode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = RSAPrivateKey::fromDER($pem->data());
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @return RSAPrivateKey
     *
     * @test
     */
    public function fromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = RSAPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function toPEM(RSAPrivateKey $pk)
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
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $this->assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pk = RSAPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function getPublicKey(RSAPrivateKey $pk)
    {
        $pub = $pk->publicKey();
        $ref = RSAPublicKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem'));
        $this->assertEquals($ref, $pub);
    }

    /**
     * @test
     */
    public function invalidVersion()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, new Integer(1));
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromASN1($seq);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromPEM($pem);
    }

    /**
     * @test
     */
    public function eCKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromPEM($pem);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function modulus(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->modulus());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function publicExponent(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->publicExponent());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function privateExponent(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->privateExponent());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function prime1(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->prime1());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function prime2(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->prime2());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function exponent1(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->exponent1());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function exponent2(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->exponent2());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function coefficient(RSAPrivateKey $pk)
    {
        $this->assertNotEmpty($pk->coefficient());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function privateKeyInfo(RSAPrivateKey $pk)
    {
        $pki = $pk->privateKeyInfo();
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }
}
