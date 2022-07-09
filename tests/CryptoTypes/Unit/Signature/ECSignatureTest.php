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
     *
     * @test
     */
    public function create()
    {
        $sig = new ECSignature('123456789', '987654321');
        $this->assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(ECSignature $sig)
    {
        $el = $sig->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toDER(ECSignature $sig)
    {
        $der = $sig->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends toDER
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $sig = ECSignature::fromDER($data);
        $this->assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(ECSignature $ref, ECSignature $sig)
    {
        $this->assertEquals($ref, $sig);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rValue(ECSignature $sig)
    {
        $this->assertEquals('123456789', $sig->r());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function sValue(ECSignature $sig)
    {
        $this->assertEquals('987654321', $sig->s());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(ECSignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
}
