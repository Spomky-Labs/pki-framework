<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Signature\GenericSignature;

/**
 * @internal
 */
final class GenericSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function create(): GenericSignature
    {
        $sig = GenericSignature::create(BitString::create('test'), SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        static::assertInstanceOf(GenericSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(GenericSignature $sig)
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function signatureAlgorithm(GenericSignature $sig)
    {
        static::assertInstanceOf(AlgorithmIdentifier::class, $sig->signatureAlgorithm());
    }
}
