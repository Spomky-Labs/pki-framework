<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Attribute\OneAsymmetricKeyAttributes;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use UnexpectedValueException;

/**
 * @internal
 */
final class PrivateKeyInfoTest extends TestCase
{
    /**
     * @return PrivateKeyInfo
     *
     * @test
     */
    public function decodeRSA()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function algoObj(PrivateKeyInfo $pki)
    {
        $ref = new RSAEncryptionAlgorithmIdentifier();
        $algo = $pki->algorithmIdentifier();
        static::assertEquals($ref, $algo);
        return $algo;
    }

    /**
     * @depends algoObj
     *
     * @test
     */
    public function algoOID(AlgorithmIdentifier $algo)
    {
        static::assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function getRSAPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function privateKeyData(PrivateKeyInfo $pki)
    {
        static::assertIsString($pki->privateKeyData());
    }

    /**
     * @return PrivateKeyInfo
     *
     * @test
     */
    public function decodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends decodeEC
     *
     * @test
     */
    public function getECPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends getECPrivateKey
     *
     * @test
     */
    public function eCPrivateKeyHasNamedCurve(ECPrivateKey $pk)
    {
        static::assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function getRSAPublicKeyInfo(PrivateKeyInfo $pki)
    {
        static::assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @depends decodeEC
     *
     * @test
     */
    public function getECPublicKeyInfo(PrivateKeyInfo $pki)
    {
        static::assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @return PrivateKeyInfo
     *
     * @test
     */
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends fromRSAPEM
     *
     * @test
     */
    public function toPEM(PrivateKeyInfo $pki)
    {
        $pem = $pki->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends toPEM
     *
     * @test
     */
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        static::assertEquals($ref, $pem);
    }

    /**
     * @test
     */
    public function fromRSAPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    /**
     * @test
     */
    public function fromECPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function version(PrivateKeyInfo $pki)
    {
        static::assertEquals(PrivateKeyInfo::VERSION_1, $pki->version());
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function invalidVersion(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $seq = $seq->withReplaced(0, new Integer(2));
        $this->expectException(UnexpectedValueException::class);
        PrivateKeyInfo::fromASN1($seq);
    }

    /**
     * @test
     */
    public function invalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PrivateKeyInfo::fromPEM($pem);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function invalidAI(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(1)
            ->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $seq = $seq->withReplaced(1, $ai);
        $this->expectException(RuntimeException::class);
        PrivateKeyInfo::fromASN1($seq)->privateKey();
    }

    /**
     * @test
     */
    public function invalidECAlgoFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $data = $seq->at(2)
            ->asOctetString()
            ->string();
        $pki = new PrivateKeyInfo(new PrivateKeyInfoTestInvalidECAlgo(), $data);
        $this->expectException(RuntimeException::class);
        $pki->privateKey();
    }

    /**
     * @test
     */
    public function encodeAttributes(): PEM
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $ref = PrivateKeyInfo::fromPEM($pem);
        $attribs = OneAsymmetricKeyAttributes::fromAttributeValues(CommonNameValue::create('John Doe'));
        $pki = new PrivateKeyInfo($ref->algorithmIdentifier(), $ref->privateKeyData(), $attribs);
        $pem = $pki->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends encodeAttributes
     *
     * @test
     */
    public function attributes(PEM $pem)
    {
        $pki = PrivateKeyInfo::fromPEM($pem);
        $value = $pki->attributes()
            ->firstOf(AttributeType::OID_COMMON_NAME)
            ->first()
            ->stringValue();
        static::assertEquals('John Doe', $value);
    }

    /**
     * @depends decodeRSA
     *
     * @test
     */
    public function hasNoAttributes(PrivateKeyInfo $pki)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pki->attributes();
    }
}
