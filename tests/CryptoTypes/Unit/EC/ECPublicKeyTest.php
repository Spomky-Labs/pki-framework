<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\EC;

use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class ECPublicKeyTest extends TestCase
{
    /**
     * @return ECPublicKey
     *
     * @test
     */
    public function fromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pk = ECPublicKey::fromPEM($pem);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function eCPoint(ECPublicKey $pk)
    {
        $this->assertNotEmpty($pk->ECPoint());
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function publicKeyInfo(ECPublicKey $pk)
    {
        $pki = $pk->publicKeyInfo();
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
    }

    /**
     * @test
     */
    public function noNamedCurve()
    {
        $pk = new ECPublicKey("\x04\0\0");
        $this->expectException(LogicException::class);
        $pk->publicKeyInfo();
    }

    /**
     * @test
     */
    public function invalidECPoint()
    {
        $this->expectException(InvalidArgumentException::class);
        new ECPublicKey("\x0");
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        ECPublicKey::fromPEM($pem);
    }

    /**
     * @test
     */
    public function rSAKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $this->expectException(UnexpectedValueException::class);
        ECPublicKey::fromPEM($pem);
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function toDER(ECPublicKey $pk)
    {
        $this->assertNotEmpty($pk->toDER());
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function curvePoint(ECPublicKey $pk)
    {
        $point = $pk->curvePoint();
        $this->assertContainsOnly('string', $point);
        return $point;
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function hasNamedCurve(ECPublicKey $pk)
    {
        $this->assertTrue($pk->hasNamedCurve());
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function namedCurve(ECPublicKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @test
     */
    public function noCurveFail()
    {
        $pk = new ECPublicKey("\x4\0\0");
        $this->expectException(LogicException::class);
        $pk->namedCurve();
    }

    /**
     * @test
     */
    public function compressedFail()
    {
        $pk = new ECPublicKey("\x3\0");
        $this->expectException(RuntimeException::class);
        $pk->curvePoint();
    }

    /**
     * @depends curvePoint
     *
     * @test
     */
    public function fromCoordinates(array $points)
    {
        [$x, $y] = $points;
        $pk = ECPublicKey::fromCoordinates($x, $y, ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromPEM
     * @depends fromCoordinates
     *
     * @test
     */
    public function fromCoordsEqualsPEM(ECPublicKey $ref, ECPublicKey $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @test
     */
    public function fromCoordsUnknownCurve()
    {
        $pk = ECPublicKey::fromCoordinates(0, 0, '1.3.6.1.3');
        $this->assertInstanceOf(ECPublicKey::class, $pk);
    }
}
