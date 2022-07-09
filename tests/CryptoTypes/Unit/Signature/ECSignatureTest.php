<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\ECSignature;

/**
 * @internal
 */
final class ECSignatureTest extends TestCase
{
    /**
     * @return ECSignature
     */
    public function testCreate()
    {
        $sig = new ECSignature('123456789', '987654321');
        $this->assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(ECSignature $sig)
    {
        $el = $sig->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
    }

    /**
     * @depends testCreate
     */
    public function testToDER(ECSignature $sig)
    {
        $der = $sig->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testToDER
     *
     * @param string $data
     */
    public function testDecode($data)
    {
        $sig = ECSignature::fromDER($data);
        $this->assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(ECSignature $ref, ECSignature $sig)
    {
        $this->assertEquals($ref, $sig);
    }

    /**
     * @depends testCreate
     */
    public function testRValue(ECSignature $sig)
    {
        $this->assertEquals('123456789', $sig->r());
    }

    /**
     * @depends testCreate
     */
    public function testSValue(ECSignature $sig)
    {
        $this->assertEquals('987654321', $sig->s());
    }

    /**
     * @depends testCreate
     */
    public function testBitString(ECSignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
}
