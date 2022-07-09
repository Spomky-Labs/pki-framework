<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\Signature\ECSignature;

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
        static::assertInstanceOf(ECSignature::class, $sig);
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
        static::assertInstanceOf(Sequence::class, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toDER(ECSignature $sig)
    {
        $der = $sig->toDER();
        static::assertIsString($der);
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
        static::assertInstanceOf(ECSignature::class, $sig);
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
        static::assertEquals($ref, $sig);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rValue(ECSignature $sig)
    {
        static::assertEquals('123456789', $sig->r());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function sValue(ECSignature $sig)
    {
        static::assertEquals('987654321', $sig->s());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(ECSignature $sig)
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }
}
