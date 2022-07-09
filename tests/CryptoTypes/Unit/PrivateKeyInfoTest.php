<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit;

use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\Attribute\OneAsymmetricKeyAttributes;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\CryptoTypes\Asymmetric\PublicKeyInfo;
use Sop\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use UnexpectedValueException;

/**
 * @internal
 */
final class PrivateKeyInfoTest extends TestCase
{
    /**
     * @return PrivateKeyInfo
     */
    public function testDecodeRSA()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testDecodeRSA
     */
    public function testAlgoObj(PrivateKeyInfo $pki)
    {
        $ref = new RSAEncryptionAlgorithmIdentifier();
        $algo = $pki->algorithmIdentifier();
        $this->assertEquals($ref, $algo);
        return $algo;
    }

    /**
     * @depends testAlgoObj
     */
    public function testAlgoOID(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @depends testDecodeRSA
     */
    public function testGetRSAPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        $this->assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    /**
     * @depends testDecodeRSA
     */
    public function testPrivateKeyData(PrivateKeyInfo $pki)
    {
        $this->assertIsString($pki->privateKeyData());
    }

    /**
     * @return PrivateKeyInfo
     */
    public function testDecodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testDecodeEC
     */
    public function testGetECPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        $this->assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    /**
     * @depends testGetECPrivateKey
     */
    public function testECPrivateKeyHasNamedCurve(ECPrivateKey $pk)
    {
        $this->assertEquals(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    /**
     * @depends testDecodeRSA
     */
    public function testGetRSAPublicKeyInfo(PrivateKeyInfo $pki)
    {
        $this->assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @depends testDecodeEC
     */
    public function testGetECPublicKeyInfo(PrivateKeyInfo $pki)
    {
        $this->assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @return PrivateKeyInfo
     */
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testFromRSAPEM
     */
    public function testToPEM(PrivateKeyInfo $pki)
    {
        $pem = $pki->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     */
    public function testRecodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $this->assertEquals($ref, $pem);
    }

    public function testFromRSAPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    public function testFromECPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    /**
     * @depends testDecodeRSA
     */
    public function testVersion(PrivateKeyInfo $pki)
    {
        $this->assertEquals(PrivateKeyInfo::VERSION_1, $pki->version());
    }

    /**
     * @depends testDecodeRSA
     */
    public function testInvalidVersion(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $seq = $seq->withReplaced(0, new Integer(2));
        $this->expectException(UnexpectedValueException::class);
        PrivateKeyInfo::fromASN1($seq);
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PrivateKeyInfo::fromPEM($pem);
    }

    /**
     * @depends testDecodeRSA
     */
    public function testInvalidAI(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(1)
            ->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $seq = $seq->withReplaced(1, $ai);
        $this->expectException(RuntimeException::class);
        PrivateKeyInfo::fromASN1($seq)->privateKey();
    }

    public function testInvalidECAlgoFail()
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

    public function testEncodeAttributes(): PEM
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $ref = PrivateKeyInfo::fromPEM($pem);
        $attribs = OneAsymmetricKeyAttributes::fromAttributeValues(new CommonNameValue('John Doe'));
        $pki = new PrivateKeyInfo($ref->algorithmIdentifier(), $ref->privateKeyData(), $attribs);
        $pem = $pki->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testEncodeAttributes
     */
    public function testAttributes(PEM $pem)
    {
        $pki = PrivateKeyInfo::fromPEM($pem);
        $value = $pki->attributes()
            ->firstOf(AttributeType::OID_COMMON_NAME)
            ->first()
            ->stringValue();
        $this->assertEquals('John Doe', $value);
    }

    /**
     * @depends testDecodeRSA
     */
    public function testHasNoAttributes(PrivateKeyInfo $pki)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pki->attributes();
    }
}
