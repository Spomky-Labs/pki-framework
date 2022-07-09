<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Signature;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\SHA384AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA384AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA224WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SignatureAlgorithmIdentifierFactory;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class SignatureFactoryTest extends TestCase
{
    /**
     * @dataProvider provideAlgoForAsymmetricCrypto
     *
     * @param AsymmetricCryptoAlgorithmIdentifier $crypto_algo
     * @param HashAlgorithmIdentifier $hash_algo
     * @param string $expected_class
     *
     * @test
     */
    public function algoForAsymmetricCrypto($crypto_algo, $hash_algo, $expected_class)
    {
        $algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto($crypto_algo, $hash_algo);
        static::assertInstanceOf($expected_class, $algo);
    }

    public function provideAlgoForAsymmetricCrypto(): iterable
    {
        $rsa = new RSAEncryptionAlgorithmIdentifier();
        $ec = new ECPublicKeyAlgorithmIdentifier(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $md5 = new MD5AlgorithmIdentifier();
        $sha1 = new SHA1AlgorithmIdentifier();
        $sha224 = new SHA224AlgorithmIdentifier();
        $sha256 = new SHA256AlgorithmIdentifier();
        $sha384 = new SHA384AlgorithmIdentifier();
        $sha512 = new SHA512AlgorithmIdentifier();
        yield [$rsa, $md5, MD5WithRSAEncryptionAlgorithmIdentifier::class];
        yield [$rsa, $sha1, SHA1WithRSAEncryptionAlgorithmIdentifier::class];
        yield [$rsa, $sha224, SHA224WithRSAEncryptionAlgorithmIdentifier::class];
        yield [$rsa, $sha256, SHA256WithRSAEncryptionAlgorithmIdentifier::class];
        yield [$rsa, $sha384, SHA384WithRSAEncryptionAlgorithmIdentifier::class];
        yield [$rsa, $sha512, SHA512WithRSAEncryptionAlgorithmIdentifier::class];
        yield [$ec, $sha1, ECDSAWithSHA1AlgorithmIdentifier::class];
        yield [$ec, $sha224, ECDSAWithSHA224AlgorithmIdentifier::class];
        yield [$ec, $sha256, ECDSAWithSHA256AlgorithmIdentifier::class];
        yield [$ec, $sha384, ECDSAWithSHA384AlgorithmIdentifier::class];
        yield [$ec, $sha512, ECDSAWithSHA512AlgorithmIdentifier::class];
    }

    /**
     * @test
     */
    public function invalidCryptoAlgo()
    {
        $crypto_algo = new SignatureFactoryTest_InvalidCryptoAlgo();
        $hash_algo = new MD5AlgorithmIdentifier();
        $this->expectException(UnexpectedValueException::class);
        SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto($crypto_algo, $hash_algo);
    }

    /**
     * @test
     */
    public function invalidRSAHashAlgo()
    {
        $crypto_algo = new RSAEncryptionAlgorithmIdentifier();
        $hash_algo = new SignatureFactoryTest_InvalidHashAlgo();
        $this->expectException(UnexpectedValueException::class);
        SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto($crypto_algo, $hash_algo);
    }

    /**
     * @test
     */
    public function invalidECHashAlgo()
    {
        $crypto_algo = new ECPublicKeyAlgorithmIdentifier(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $hash_algo = new SignatureFactoryTest_InvalidHashAlgo();
        $this->expectException(UnexpectedValueException::class);
        SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto($crypto_algo, $hash_algo);
    }
}

class SignatureFactoryTest_InvalidCryptoAlgo extends SpecificAlgorithmIdentifier implements AsymmetricCryptoAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = '1.3.6.1.3';
    }

    public function name(): string
    {
        return 'test';
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}

class SignatureFactoryTest_InvalidHashAlgo extends SpecificAlgorithmIdentifier implements HashAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = '1.3.6.1.3';
    }

    public function name(): string
    {
        return 'test';
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        throw new BadMethodCallException(__FUNCTION__ . ' must be implemented in derived class.');
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
