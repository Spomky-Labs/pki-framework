<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\EC;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function decode(): ECPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromDER($pem->data());
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    public function fromPEM(): ECPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromPEM')]
    public function toPEM(ECPrivateKey $pk): PEM
    {
        $pem = $pk->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function recodedPEM(PEM $pem): void
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        static::assertEquals($ref, $pem);
    }

    #[Test]
    public function fromPKIPEM(): ECPrivateKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('decode')]
    public function privateKeyOctets(ECPrivateKey $pk): void
    {
        $octets = $pk->privateKeyOctets();
        static::assertIsString($octets);
    }

    #[Test]
    #[Depends('fromPKIPEM')]
    public function hasNamedCurveFromPKI(ECPrivateKey $pk): void
    {
        static::assertSame(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    #[Test]
    #[Depends('decode')]
    public function getPublicKey(ECPrivateKey $pk): void
    {
        $pub = $pk->publicKey();
        $ref = ECPublicKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem'));
        static::assertEquals($ref, $pub);
    }

    #[Test]
    #[Depends('decode')]
    public function getPrivateKeyInfo(ECPrivateKey $pk): void
    {
        $pki = $pk->privateKeyInfo();
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    #[Test]
    public function invalidVersion(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, Integer::create(0));
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromASN1($seq);
    }

    #[Test]
    public function invalidPEMType(): void
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    #[Test]
    public function rSAKeyFail(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    #[Test]
    #[Depends('decode')]
    public function namedCurveNotSet(ECPrivateKey $pk)
    {
        $pk = $pk->withNamedCurve(null);
        $this->expectException(LogicException::class);
        $pk->namedCurve();
    }

    #[Test]
    public function publicKeyNotSet()
    {
        $pk = ECPrivateKey::create("\0");
        $this->expectException(LogicException::class);
        $pk->publicKey();
    }
}
