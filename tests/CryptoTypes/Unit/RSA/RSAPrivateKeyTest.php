<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
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
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
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
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
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
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        static::assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pk = RSAPrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
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
        static::assertEquals($ref, $pub);
    }

    /**
     * @test
     */
    public function invalidVersion()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, Integer::create(1));
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromASN1($seq);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
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
        static::assertNotEmpty($pk->modulus());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function publicExponent(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->publicExponent());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function privateExponent(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->privateExponent());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function prime1(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->prime1());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function prime2(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->prime2());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function exponent1(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->exponent1());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function exponent2(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->exponent2());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function coefficient(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->coefficient());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function privateKeyInfo(RSAPrivateKey $pk)
    {
        $pki = $pk->privateKeyInfo();
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }
}
