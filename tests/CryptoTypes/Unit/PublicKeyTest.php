<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class PublicKeyTest extends TestCase
{
    #[Test]
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pk = PublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    #[Test]
    public function fromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pk = PublicKey::fromPEM($pem);
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @return PublicKey
     */
    #[Test]
    public function fromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pk = PublicKey::fromPEM($pem);
        static::assertInstanceOf(ECPublicKey::class, $pk);
        return $pk;
    }

    #[Test]
    public function rSAPKIRecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
        static::assertEquals($pem, $result);
    }

    #[Test]
    public function eCPKIRecode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $result = PublicKey::fromPEM($pem)->publicKeyInfo()->toPEM();
        static::assertEquals($pem, $result);
    }

    #[Test]
    public function invalidPEM()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PublicKey::fromPEM($pem);
    }
}
