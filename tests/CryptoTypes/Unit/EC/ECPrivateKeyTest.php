<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\EC;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class ECPrivateKeyTest extends TestCase
{
    /**
     * @test
     */
    public function decode(): ECPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromDER($pem->data());
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @test
     */
    public function fromPEM(): ECPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function toPEM(ECPrivateKey $pk): PEM
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
    public function recodedPEM(PEM $pem): void
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        static::assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function fromPKIPEM(): ECPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function privateKeyOctets(ECPrivateKey $pk): void
    {
        $octets = $pk->privateKeyOctets();
        static::assertIsString($octets);
    }

    /**
     * @depends fromPKIPEM
     *
     * @test
     */
    public function hasNamedCurveFromPKI(ECPrivateKey $pk): void
    {
        static::assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function getPublicKey(ECPrivateKey $pk): void
    {
        $pub = $pk->publicKey();
        $ref = ECPublicKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem'));
        static::assertEquals($ref, $pub);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function getPrivateKeyInfo(ECPrivateKey $pk): void
    {
        $pki = $pk->privateKeyInfo();
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    /**
     * @test
     */
    public function invalidVersion(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, Integer::create(0));
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromASN1($seq);
    }

    /**
     * @test
     */
    public function invalidPEMType(): void
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    /**
     * @test
     */
    public function rSAKeyFail(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function namedCurveNotSet(ECPrivateKey $pk)
    {
        $pk = $pk->withNamedCurve(null);
        $this->expectException(LogicException::class);
        $pk->namedCurve();
    }

    /**
     * @test
     */
    public function publicKeyNotSet()
    {
        $pk = ECPrivateKey::create("\0");
        $this->expectException(LogicException::class);
        $pk->publicKey();
    }
}
