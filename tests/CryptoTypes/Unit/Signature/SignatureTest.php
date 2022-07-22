<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed25519AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Signature\ECSignature;
use SpomkyLabs\Pki\CryptoTypes\Signature\Ed25519Signature;
use SpomkyLabs\Pki\CryptoTypes\Signature\Ed448Signature;
use SpomkyLabs\Pki\CryptoTypes\Signature\GenericSignature;
use SpomkyLabs\Pki\CryptoTypes\Signature\RSASignature;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;

/**
 * @internal
 */
final class SignatureTest extends TestCase
{
    /**
     * @test
     */
    public function fromRSAAlgo()
    {
        $sig = Signature::fromSignatureData('test', SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        static::assertInstanceOf(RSASignature::class, $sig);
    }

    /**
     * @test
     */
    public function fromECAlgo()
    {
        $seq = Sequence::create(new Integer(1), new Integer(2));
        $sig = Signature::fromSignatureData($seq->toDER(), ECDSAWithSHA1AlgorithmIdentifier::create());
        static::assertInstanceOf(ECSignature::class, $sig);
    }

    /**
     * @test
     */
    public function fromEd25519Algo()
    {
        $sig = Signature::fromSignatureData(str_repeat("\0", 64), Ed25519AlgorithmIdentifier::create());
        static::assertInstanceOf(Ed25519Signature::class, $sig);
    }

    /**
     * @test
     */
    public function fromEd448Algo()
    {
        $sig = Signature::fromSignatureData(str_repeat("\0", 114), Ed448AlgorithmIdentifier::create());
        static::assertInstanceOf(Ed448Signature::class, $sig);
    }

    /**
     * @test
     */
    public function fromUnknownAlgo()
    {
        $sig = Signature::fromSignatureData('', new GenericAlgorithmIdentifier('1.3.6.1.3'));
        static::assertInstanceOf(GenericSignature::class, $sig);
    }
}
