<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\EC;

use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class ECPublicKeyTest extends TestCase
{
    #[Test]
    public function fromPEM(): ECPublicKey
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pk = ECPublicKey::fromPEM($pem);
        static::assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromPEM')]
    public function eCPoint(ECPublicKey $pk)
    {
        static::assertNotEmpty($pk->ECPoint());
    }

    #[Test]
    #[Depends('fromPEM')]
    public function publicKeyInfo(ECPublicKey $pk)
    {
        $pki = $pk->publicKeyInfo();
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
    }

    #[Test]
    public function noNamedCurve()
    {
        $pk = ECPublicKey::create("\x04\0\0");
        $this->expectException(LogicException::class);
        $pk->publicKeyInfo();
    }

    #[Test]
    public function invalidECPoint()
    {
        $this->expectException(InvalidArgumentException::class);
        ECPublicKey::create("\x0");
    }

    #[Test]
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        ECPublicKey::fromPEM($pem);
    }

    #[Test]
    public function rSAKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $this->expectException(UnexpectedValueException::class);
        ECPublicKey::fromPEM($pem);
    }

    #[Test]
    #[Depends('fromPEM')]
    public function toDER(ECPublicKey $pk)
    {
        static::assertNotEmpty($pk->toDER());
    }

    #[Test]
    #[Depends('fromPEM')]
    public function curvePoint(ECPublicKey $pk)
    {
        $point = $pk->curvePoint();
        static::assertContainsOnly('string', $point);
        return $point;
    }

    #[Test]
    #[Depends('fromPEM')]
    public function hasNamedCurve(ECPublicKey $pk)
    {
        static::assertTrue($pk->hasNamedCurve());
    }

    #[Test]
    #[Depends('fromPEM')]
    public function namedCurve(ECPublicKey $pk)
    {
        static::assertSame(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    #[Test]
    public function noCurveFail()
    {
        $pk = ECPublicKey::create("\x4\0\0");
        $this->expectException(LogicException::class);
        $pk->namedCurve();
    }

    #[Test]
    public function compressedFail()
    {
        $pk = ECPublicKey::create("\x3\0");
        $this->expectException(RuntimeException::class);
        $pk->curvePoint();
    }

    #[Test]
    #[Depends('curvePoint')]
    public function fromCoordinates(array $points)
    {
        [$x, $y] = $points;
        $pk = ECPublicKey::fromCoordinates($x, $y, ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        static::assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromPEM')]
    #[Depends('fromCoordinates')]
    public function fromCoordsEqualsPEM(ECPublicKey $ref, ECPublicKey $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    public function fromCoordsUnknownCurve()
    {
        $pk = ECPublicKey::fromCoordinates(0, 0, '1.3.6.1.3');
        static::assertInstanceOf(ECPublicKey::class, $pk);
    }
}
