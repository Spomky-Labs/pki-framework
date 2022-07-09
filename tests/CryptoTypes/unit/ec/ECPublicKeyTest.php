<?php

declare(strict_types=1);

namespace unit\ec;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;

/**
 * @group asn1
 * @group ec
 *
 * @internal
 */
class ECPublicKeyTest extends TestCase
{
    /**
     * @return ECPublicKey
     */
    public function testFromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pk = ECPublicKey::fromPEM($pem);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testFromPEM
     */
    public function testECPoint(ECPublicKey $pk)
    {
        $this->assertNotEmpty($pk->ECPoint());
    }

    /**
     * @depends testFromPEM
     */
    public function testPublicKeyInfo(ECPublicKey $pk)
    {
        $pki = $pk->publicKeyInfo();
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
    }

    public function testNoNamedCurve()
    {
        $pk = new ECPublicKey("\x04\0\0");
        $this->expectException(\LogicException::class);
        $pk->publicKeyInfo();
    }

    public function testInvalidECPoint()
    {
        $this->expectException(\InvalidArgumentException::class);
        new ECPublicKey("\x0");
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        ECPublicKey::fromPEM($pem);
    }

    public function testRSAKeyFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $this->expectException(\UnexpectedValueException::class);
        ECPublicKey::fromPEM($pem);
    }

    /**
     * @depends testFromPEM
     */
    public function testToDER(ECPublicKey $pk)
    {
        $this->assertNotEmpty($pk->toDER());
    }

    /**
     * @depends testFromPEM
     */
    public function testCurvePoint(ECPublicKey $pk)
    {
        $point = $pk->curvePoint();
        $this->assertContainsOnly('string', $point);
        return $point;
    }

    /**
     * @depends testFromPEM
     */
    public function testHasNamedCurve(ECPublicKey $pk)
    {
        $this->assertTrue($pk->hasNamedCurve());
    }

    /**
     * @depends testFromPEM
     */
    public function testNamedCurve(ECPublicKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1,
            $pk->namedCurve());
    }

    public function testNoCurveFail()
    {
        $pk = new ECPublicKey("\x4\0\0");
        $this->expectException(\LogicException::class);
        $pk->namedCurve();
    }

    public function testCompressedFail()
    {
        $pk = new ECPublicKey("\x3\0");
        $this->expectException(\RuntimeException::class);
        $pk->curvePoint();
    }

    /**
     * @depends testCurvePoint
     */
    public function testFromCoordinates(array $points)
    {
        [$x, $y] = $points;
        $pk = ECPublicKey::fromCoordinates($x, $y,
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $this->assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testFromPEM
     * @depends testFromCoordinates
     */
    public function testFromCoordsEqualsPEM(ECPublicKey $ref, ECPublicKey $new)
    {
        $this->assertEquals($ref, $new);
    }

    public function testFromCoordsUnknownCurve()
    {
        $pk = ECPublicKey::fromCoordinates(0, 0, '1.3.6.1.3');
        $this->assertInstanceOf(ECPublicKey::class, $pk);
    }
}
