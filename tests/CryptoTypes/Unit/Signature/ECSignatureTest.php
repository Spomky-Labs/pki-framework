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
     * @test
     */
    public function create(): ECSignature
    {
        $sig = ECSignature::create('123456789', '987654321');
        static::assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(ECSignature $sig): void
    {
        $el = $sig->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toDER(ECSignature $sig): string
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
    public function decode($data): ECSignature
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
    public function recoded(ECSignature $ref, ECSignature $sig): void
    {
        static::assertEquals($ref, $sig);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rValue(ECSignature $sig): void
    {
        static::assertEquals('123456789', $sig->r());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function sValue(ECSignature $sig): void
    {
        static::assertEquals('987654321', $sig->s());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(ECSignature $sig): void
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }
}
