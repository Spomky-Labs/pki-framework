<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\GenericSignature;

/**
 * @internal
 */
final class GenericSignatureTest extends TestCase
{
    /**
     * @return GenericSignature
     *
     * @test
     */
    public function create()
    {
        $sig = new GenericSignature(new BitString('test'), new SHA1WithRSAEncryptionAlgorithmIdentifier());
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
