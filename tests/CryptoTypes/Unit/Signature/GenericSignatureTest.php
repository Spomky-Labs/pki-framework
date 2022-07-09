<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\GenericSignature;

/**
 * @group signature
 *
 * @internal
 */
class GenericSignatureTest extends TestCase
{
    /**
     * @return GenericSignature
     */
    public function testCreate()
    {
        $sig = new GenericSignature(new BitString('test'),
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(GenericSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     */
    public function testBitString(GenericSignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }

    /**
     * @depends testCreate
     */
    public function testSignatureAlgorithm(GenericSignature $sig)
    {
        $this->assertInstanceOf(AlgorithmIdentifier::class,
            $sig->signatureAlgorithm());
    }
}
