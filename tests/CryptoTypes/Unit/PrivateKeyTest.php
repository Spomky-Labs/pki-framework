<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class PrivateKeyTest extends TestCase
{
    #[Test]
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    #[Test]
    public function fromRSAPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @return PrivateKey
     */
    #[Test]
    public function fromECPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromECPEM')]
    public function eCPEMHasNamedCurve(ECPrivateKey $pk)
    {
        static::assertSame(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @return PrivateKey
     */
    #[Test]
    public function fromECPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = PrivateKey::fromPEM($pem);
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('fromECPKIPEM')]
    public function eCPKIPEMHasNamedCurve(ECPrivateKey $pk)
    {
        static::assertSame(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    #[Test]
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PrivateKey::fromPEM($pem);
    }
}
