<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use UnexpectedValueException;

/**
 * @group asn1
 * @group privatekey
 *
 * @internal
 */
class PrivateKeyTest extends TestCase
{
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    public function testFromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @return PrivateKey
     */
    public function testFromECPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testFromECPEM
     */
    public function testECPEMHasNamedCurve(ECPrivateKey $pk)
    {
        $this->assertEquals(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1,
            $pk->namedCurve()
        );
    }

    /**
     * @return PrivateKey
     */
    public function testFromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testFromECPKIPEM
     */
    public function testECPKIPEMHasNamedCurve(ECPrivateKey $pk)
    {
        $this->assertEquals(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1,
            $pk->namedCurve()
        );
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        PrivateKey::fromPEM($pem);
    }
}
