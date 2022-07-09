<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\BitString;

use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class BitStringTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new BitString('');
        $this->assertInstanceOf(BitString::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_BIT_STRING, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): BitString
    {
        $el = BitString::fromDER($data);
        $this->assertInstanceOf(BitString::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        $this->assertEquals($ref, $el);
    }

    /**
     * @dataProvider ffProvider
     *
     * @test
     */
    public function range8(int $start, int $length, string $result)
    {
        $bs = new BitString("\xff");
        $this->assertEquals($result, $bs->range($start, $length));
    }

    public function ffProvider(): array
    {
        return [[0, 8, strval(0xff)], [1, 2, strval(0x03)], [6, 2, strval(0x03)], [2, 4, strval(0x0f)]];
    }

    /**
     * @dataProvider ffffProvider
     *
     * @test
     */
    public function range16(int $start, int $length, string $result)
    {
        $bs = new BitString("\xff\xff");
        $this->assertEquals($result, $bs->range($start, $length));
    }

    public function ffffProvider(): array
    {
        return [[0, 8, strval(0xff)], [6, 4, strval(0x0f)], [12, 4, strval(0x0f)]];
    }

    /**
     * @test
     */
    public function emptyRange()
    {
        $bs = new BitString("\0");
        $this->assertEquals(0, $bs->range(0, 0));
    }

    /**
     * @test
     */
    public function rangeOOB()
    {
        $bs = new BitString("\xff");
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Not enough bits');
        $bs->range(7, 2);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(BitString::class, $wrap->asBitString());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('BIT STRING expected, got primitive NULL');
        $wrap->asBitString();
    }
}
