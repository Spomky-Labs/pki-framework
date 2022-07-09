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
 * @internal
 */
final class PrivateKeyTest extends TestCase
{
    /**
     * @test
     */
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @test
     */
    public function fromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @return PrivateKey
     *
     * @test
     */
    public function fromECPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromECPEM
     *
     * @test
     */
    public function eCPEMHasNamedCurve(ECPrivateKey $pk)
    {
        static::assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @return PrivateKey
     *
     * @test
     */
    public function fromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromECPKIPEM
     *
     * @test
     */
    public function eCPKIPEMHasNamedCurve(ECPrivateKey $pk)
    {
        static::assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PrivateKey::fromPEM($pem);
    }
}
