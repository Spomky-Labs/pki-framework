<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\RSA;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function decode(): RSAPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = RSAPrivateKey::fromDER($pem->data());
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    public function fromPEM(): RSAPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = RSAPrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromPEM')]
    public function toPEM(RSAPrivateKey $pk): PEM
    {
        $pem = $pk->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        static::assertEquals($ref, $pem);
    }

    #[Test]
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pk = RSAPrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    #[Test]
    #[Depends('decode')]
    public function getPublicKey(RSAPrivateKey $pk)
    {
        $pub = $pk->publicKey();
        $ref = RSAPublicKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem'));
        static::assertEquals($ref, $pub);
    }

    #[Test]
    public function invalidVersion()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, Integer::create(1));
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromASN1($seq);
    }

    #[Test]
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromPEM($pem);
    }

    #[Test]
    public function eCKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $this->expectException(UnexpectedValueException::class);
        RSAPrivateKey::fromPEM($pem);
    }

    #[Test]
    #[Depends('decode')]
    public function modulus(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->modulus());
    }

    #[Test]
    #[Depends('decode')]
    public function publicExponent(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->publicExponent());
    }

    #[Test]
    #[Depends('decode')]
    public function privateExponent(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->privateExponent());
    }

    #[Test]
    #[Depends('decode')]
    public function prime1(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->prime1());
    }

    #[Test]
    #[Depends('decode')]
    public function prime2(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->prime2());
    }

    #[Test]
    #[Depends('decode')]
    public function exponent1(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->exponent1());
    }

    #[Test]
    #[Depends('decode')]
    public function exponent2(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->exponent2());
    }

    #[Test]
    #[Depends('decode')]
    public function coefficient(RSAPrivateKey $pk)
    {
        static::assertNotEmpty($pk->coefficient());
    }

    #[Test]
    #[Depends('decode')]
    public function privateKeyInfo(RSAPrivateKey $pk)
    {
        $pki = $pk->privateKeyInfo();
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }
}
