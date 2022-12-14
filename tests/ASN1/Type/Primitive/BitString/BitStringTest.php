<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\BitString;

use OutOfBoundsException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function strval;
use UnexpectedValueException;

/**
 * @internal
 */
final class BitStringTest extends TestCase
{
    #[Test]
    public function create()
    {
        $el = BitString::create('');
        static::assertInstanceOf(BitString::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_BIT_STRING, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): BitString
    {
        $el = BitString::fromDER($data);
        static::assertInstanceOf(BitString::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    #[Test]
    #[DataProvider('ffProvider')]
    public function range8(int $start, int $length, string $result)
    {
        $bs = BitString::create("\xff");
        static::assertEquals($result, $bs->range($start, $length));
    }

    public static function ffProvider(): array
    {
        return [[0, 8, strval(0xff)], [1, 2, strval(0x03)], [6, 2, strval(0x03)], [2, 4, strval(0x0f)]];
    }

    #[Test]
    #[DataProvider('ffffProvider')]
    public function range16(int $start, int $length, string $result)
    {
        $bs = BitString::create("\xff\xff");
        static::assertEquals($result, $bs->range($start, $length));
    }

    public static function ffffProvider(): array
    {
        return [[0, 8, strval(0xff)], [6, 4, strval(0x0f)], [12, 4, strval(0x0f)]];
    }

    #[Test]
    public function emptyRange()
    {
        $bs = BitString::create("\0");
        static::assertEquals(0, $bs->range(0, 0));
    }

    #[Test]
    public function rangeOOB()
    {
        $bs = BitString::create("\xff");
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Not enough bits');
        $bs->range(7, 2);
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(BitString::class, $wrap->asBitString());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('BIT STRING expected, got primitive NULL');
        $wrap->asBitString();
    }
}
