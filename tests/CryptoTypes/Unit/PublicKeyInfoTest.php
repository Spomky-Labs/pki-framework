<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit;

use BadMethodCallException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECPublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use UnexpectedValueException;
use function mb_strlen;

/**
 * @internal
 */
final class PublicKeyInfoTest extends TestCase
{
    #[Test]
    public function decodeRSA(): PublicKeyInfo
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pki = PublicKeyInfo::fromDER($pem->data());
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function algoObj(PublicKeyInfo $pki): AlgorithmIdentifierType
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
    public function getRSAPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        static::assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @return PublicKeyInfo
     */
    #[Test]
    public function decodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pki = PublicKeyInfo::fromDER($pem->data());
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('decodeEC')]
    public function getECPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        static::assertInstanceOf(ECPublicKey::class, $pk);
    }

    /**
     * @return PublicKeyInfo
     */
    #[Test]
    public function fromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pki = PublicKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    #[Test]
    #[Depends('fromRSAPEM')]
    public function toPEM(PublicKeyInfo $pki)
    {
        $pem = $pki->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function recodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        static::assertEquals($ref, $pem);
    }

    #[Test]
    public function decodeFromRSAPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pki = PublicKeyInfo::fromPEM($pem);
        static::assertInstanceOf(PublicKeyInfo::class, $pki);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function keyIdentifier(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier();
        static::assertSame(160, mb_strlen($id, '8bit') * 8);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function keyIdentifier64(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier64();
        static::assertSame(64, mb_strlen($id, '8bit') * 8);
    }

    #[Test]
    public function invalidPEMType()
    {
        $pem = PEM::create('nope', '');
        $this->expectException(UnexpectedValueException::class);
        PublicKeyInfo::fromPEM($pem);
    }

    #[Test]
    #[Depends('decodeRSA')]
    public function invalidAI(PublicKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(0)
            ->asSequence()
            ->withReplaced(0, ObjectIdentifier::create('1.3.6.1.3'));
        $seq = $seq->withReplaced(0, $ai);
        $this->expectException(RuntimeException::class);
        PublicKeyInfo::fromASN1($seq)->publicKey();
    }

    #[Test]
    public function invalidECAlgoFail()
    {
        $pki = PublicKeyInfo::create(new PubliceKeyInfoTest_InvalidECAlgo(), BitString::create(''));
        $this->expectException(UnexpectedValueException::class);
        $pki->publicKey();
    }
}

class PubliceKeyInfoTest_InvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        parent::__construct(self::OID_EC_PUBLIC_KEY);
    }

    public function name(): string
    {
        return '';
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function paramsASN1(): ?Element
    {
        return null;
    }
}
