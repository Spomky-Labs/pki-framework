<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class PublicKeyTest extends TestCase
{
    /**
     * @test
     */
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = PublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @test
     */
    public function fromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pk = PublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @return PublicKey
     *
     * @test
     */
    public function fromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pk = PublicKey::fromPEM($pem);
        static::assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    /**
     * @test
     */
    public function rSAPKIRecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
        static::assertEquals($pem, $result);
    }

    /**
     * @test
     */
    public function eCPKIRecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
        static::assertEquals($pem, $result);
    }

    /**
     * @test
     */
    public function invalidPEM()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PublicKey::fromPEM($pem);
    }
}
