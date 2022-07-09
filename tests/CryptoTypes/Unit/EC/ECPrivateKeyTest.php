<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\EC;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class ECPrivateKeyTest extends TestCase
{
    /**
     * @return ECPrivateKey
     *
     * @test
     */
    public function decode()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromDER($pem->data());
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @return ECPrivateKey
     *
     * @test
     */
    public function fromPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends fromPEM
     *
     * @test
     */
    public function toPEM(ECPrivateKey $pk)
    {
        $pem = $pk->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $this->assertEquals($ref, $pem);
    }

    /**
     * @return ECPrivateKey
     *
     * @test
     */
    public function fromPKIPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pk = ECPrivateKey::fromPEM($pem);
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function privateKeyOctets(ECPrivateKey $pk)
    {
        $octets = $pk->privateKeyOctets();
        $this->assertIsString($octets);
    }

    /**
     * @depends fromPKIPEM
     *
     * @test
     */
    public function hasNamedCurveFromPKI(ECPrivateKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function getPublicKey(ECPrivateKey $pk)
    {
        $pub = $pk->publicKey();
        $ref = ECPublicKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem'));
        $this->assertEquals($ref, $pub);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function getPrivateKeyInfo(ECPrivateKey $pk)
    {
        $pki = $pk->privateKeyInfo();
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    /**
     * @test
     */
    public function invalidVersion()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $seq = $seq->withReplaced(0, new Integer(0));
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromASN1($seq);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        ECPrivateKey::fromPEM($pem);
    }

    /**
     * @test
     */
    public function rSAKeyFail()
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
        $pk = new ECPrivateKey("\0");
        $this->expectException(LogicException::class);
        $pk->publicKey();
    }
}
