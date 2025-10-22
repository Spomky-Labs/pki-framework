<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
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
    #[Test]
    public function decodeRSA(): PrivateKeyInfo
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function algoObj(PrivateKeyInfo $pki): AlgorithmIdentifierType
    {
        $ref = RSAEncryptionAlgorithmIdentifier::create();
        $algo = $pki->algorithmIdentifier();
        static::assertEquals($ref, $algo);
        return $algo;
    }

    #[Test]
    #[Depends('algoObj')]
    public function algoOID(AlgorithmIdentifier $algo)
    {
        static::assertSame(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $algo->oid());
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function getRSAPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        static::assertInstanceOf(RSAPrivateKey::class, $pk);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function privateKeyData(PrivateKeyInfo $pki)
    {
        static::assertIsString($pki->privateKeyData());
    }

    /**
     * @return PrivateKeyInfo
     */
    #[Test]
    public function decodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $pki = PrivateKeyInfo::fromDER($pem->data());
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('decodeEC')]
    public function getECPrivateKey(PrivateKeyInfo $pki)
    {
        $pk = $pki->privateKey();
        static::assertInstanceOf(ECPrivateKey::class, $pk);
        return $pk;
    }

    #[Test]
    #[Depends('getECPrivateKey')]
    public function eCPrivateKeyHasNamedCurve(ECPrivateKey $pk)
    {
        static::assertSame(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1, $pk->namedCurve());
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function getRSAPublicKeyInfo(PrivateKeyInfo $pki)
    {
        static::assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    #[Test]
    #[Depends('decodeEC')]
    public function getECPublicKeyInfo(PrivateKeyInfo $pki)
    {
        static::assertInstanceOf(PublicKeyInfo::class, $pki->publicKeyInfo());
    }

    /**
     * @return PrivateKeyInfo
     */
    #[Test]
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('fromRSAPEM')]
    public function toPEM(PrivateKeyInfo $pki)
    {
        $pem = $pki->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem');
        static::assertEquals($ref, $pem);
    }

    #[Test]
    public function fromRSAPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    #[Test]
    public function fromECPrivateKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/ec_private_key.pem');
        $pki = PrivateKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PrivateKeyInfo::class, $pki);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function version(PrivateKeyInfo $pki)
    {
        static::assertSame(PrivateKeyInfo::VERSION_1, $pki->version());
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function invalidVersion(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $seq = $seq->withReplaced(0, Integer::create(2));
        $this->expectException(UnexpectedValueException::class);
        PrivateKeyInfo::fromASN1($seq);
    }

    #[Test]
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PrivateKeyInfo::fromPEM($pem);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function invalidAI(PrivateKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(1)
            ->asSequence()
            ->withReplaced(0, ObjectIdentifier::create('1.3.6.1.3'));
        $seq = $seq->withReplaced(1, $ai);
        $this->expectException(RuntimeException::class);
        PrivateKeyInfo::fromASN1($seq)->privateKey();
    }

    #[Test]
    public function invalidECAlgoFail()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem');
        $seq = Sequence::fromDER($pem->data());
        $data = $seq->at(2)
            ->asOctetString()
            ->string();
        $pki = PrivateKeyInfo::create(new PrivateKeyInfoTestInvalidECAlgo(), $data);
        $this->expectException(RuntimeException::class);
        $pki->privateKey();
    }

    #[Test]
    public function encodeAttributes(): PEM
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_private_key.pem');
        $ref = PrivateKeyInfo::fromPEM($pem);
        $attribs = OneAsymmetricKeyAttributes::fromAttributeValues(CommonNameValue::create('John Doe'));
        $pki = PrivateKeyInfo::create($ref->algorithmIdentifier(), $ref->privateKeyData(), $attribs);
        $pem = $pki->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('encodeAttributes')]
    public function attributes(PEM $pem)
    {
        $pki = PrivateKeyInfo::fromPEM($pem);
        $value = $pki->attributes()
            ->firstOf(AttributeType::OID_COMMON_NAME)
            ->first()
            ->stringValue();
        static::assertSame('John Doe', $value);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function hasNoAttributes(PrivateKeyInfo $pki)
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/not set/');
        $pki->attributes();
    }
}
