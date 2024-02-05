<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Real;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;
use const INF;
use const M_PI;
use const NAN;
use const PHP_FLOAT_MAX;
use const PHP_FLOAT_MIN;

/**
 * @internal
 */
final class RealTest extends TestCase
{
    #[Test]
    public function create(): Real
    {
        $el = Real::fromString('314.E-2');
        static::assertInstanceOf(Real::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Real $el)
    {
        static::assertSame(Element::TYPE_REAL, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Real $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): Real
    {
        $el = Real::fromDER($data);
        static::assertInstanceOf(Real::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Real $ref, Real $el)
    {
        static::assertSame($ref->nr3Val(), $el->nr3Val());
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(Real::class, $wrap->asReal());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('REAL expected, got primitive NULL');
        $wrap->asReal();
    }

    #[Test]
    #[Depends('create')]
    public function string(Real $el)
    {
        static::assertIsString((string) $el);
    }

    #[Test]
    #[Depends('create')]
    public function mantissa(Real $el)
    {
        static::assertSame(314, $el->mantissa()->toInt());
    }

    #[Test]
    #[Depends('create')]
    public function exponent(Real $el)
    {
        static::assertSame(-2, $el->exponent()->toInt());
    }

    #[Test]
    #[Depends('create')]
    public function base(Real $el)
    {
        static::assertSame(10, $el->base());
    }

    #[Test]
    #[DataProvider('provideFromFloat')]
    public function fromFloat(float $number)
    {
        $real = Real::fromFloat($number);
        $recoded = Real::fromDER($real->toDER());
        static::assertSame($number, $recoded->floatVal());
    }

    #[Test]
    #[DataProvider('provideFromFloat')]
    public function fromFloatNonStrict(float $number)
    {
        $real = Real::fromFloat($number)->withStrictDER(false);
        $recoded = Real::fromDER($real->toDER());
        static::assertSame($number, $recoded->floatVal());
    }

    public static function provideFromFloat(): iterable
    {
        yield [0.0];
        yield [1.0];
        yield [-1.0];
        // normalized limits
        yield [PHP_FLOAT_MAX];
        yield [-PHP_FLOAT_MAX];
        yield [PHP_FLOAT_MIN];
        yield [-PHP_FLOAT_MIN];
        // denormalized limits
        yield [4.9406564584125E-324];
        yield [-4.9406564584125E-324];
        yield [INF];
        yield [-INF];
        yield [M_PI];
        yield [-M_PI];
        // high bases
        yield [1.0E256];
        yield [-1.0E256];
        yield [1.0E-256];
        yield [-1.0E-256];
    }

    #[Test]
    public function fromFloatNAN()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NaN values not supported');
        Real::fromFloat(NAN);
    }

    #[Test]
    public function fromPartsInvalidBase()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Base must be 2 or 10');
        Real::create(1, 1, 3);
    }

    #[Test]
    public function fromNR3()
    {
        $real = Real::fromString('-123,456E-3');
        static::assertSame(-0.123456, $real->floatVal());
    }

    #[Test]
    public function fromNR3Zero()
    {
        $real = Real::fromString('0,0E1');
        static::assertSame(0.0, $real->floatVal());
    }

    #[Test]
    public function fromNR2()
    {
        $real = Real::fromString('-123,456');
        static::assertSame(-123.456, $real->floatVal());
    }

    #[Test]
    public function fromNR2Zero()
    {
        $real = Real::fromString('0,0');
        static::assertSame(0.0, $real->floatVal());
    }

    #[Test]
    public function fromNR1()
    {
        $real = Real::fromString('-123');
        static::assertEqualsWithDelta(-123, $real->floatVal(), 0.0001);
    }

    #[Test]
    public function fromNR1Zero()
    {
        $real = Real::fromString('0');
        static::assertSame(0.0, $real->floatVal());
    }

    #[Test]
    public function parseNormalize()
    {
        $real = Real::fromString('100');
        static::assertSame(2, $real->exponent()->toInt());
    }

    #[Test]
    public function parseFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('X could not be parsed to REAL');
        Real::fromString('X');
    }

    #[Test]
    public function base2ToNR3()
    {
        $real = Real::fromFloat(-123.456);
        static::assertSame('-123456.E-3', $real->nr3Val());
    }

    #[Test]
    public function nr3ShiftZeroes()
    {
        $real = Real::create(100, 0, 10);
        static::assertSame('1.E2', $real->nr3Val());
    }

    #[Test]
    public function nr3ZeroExponent()
    {
        $real = Real::create(1, 0, 10);
        static::assertSame('1.E+0', $real->nr3Val());
    }
}
