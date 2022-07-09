<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;

/**
 * @internal
 */
final class PublicKeyInfoTest extends TestCase
{
    /**
     * @return PublicKeyInfo
     *
     * @test
     */
    public function decodeRSA()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pki = PublicKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function algoObj(PublicKeyInfo $pki)
    {
        $ref = new RSAEncryptionAlgorithmIdentifier();
        $algo = $pki->algorithmIdentifier();
        $this->assertEquals($ref, $algo);
        return $algo;
    }

    /**
     * @depends algoObj
     *
     * @test
     */
    public function algoOID(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function getRSAPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @return PublicKeyInfo
     *
     * @test
     */
    public function decodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pki = PublicKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends decodeEC
     *
     * @test
     */
    public function getECPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        $this->assertInstanceOf(ECPublicKey::class, $pk);
    }

    /**
     * @return PublicKeyInfo
     *
     * @test
     */
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pki = PublicKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends fromRSAPEM
     *
     * @test
     */
    public function toPEM(PublicKeyInfo $pki)
    {
        $pem = $pki->toPEM();
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
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $this->assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function decodeFromRSAPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pki = PublicKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function keyIdentifier(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier();
        $this->assertEquals(160, strlen($id) * 8);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function keyIdentifier64(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier64();
        $this->assertEquals(64, strlen($id) * 8);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PublicKeyInfo::fromPEM($pem);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function invalidAI(PublicKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(0)
            ->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $seq = $seq->withReplaced(0, $ai);
        $this->expectException(RuntimeException::class);
        PublicKeyInfo::fromASN1($seq)->publicKey();
    }

    /**
     * @test
     */
    public function invalidECAlgoFail()
    {
        $pki = new PublicKeyInfo(new PubliceKeyInfoTest_InvalidECAlgo(), new BitString(''));
        $this->expectException(UnexpectedValueException::class);
        $pki->publicKey();
    }
}

class PubliceKeyInfoTest_InvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_EC_PUBLIC_KEY;
    }

    public function name(): string
    {
        return '';
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
