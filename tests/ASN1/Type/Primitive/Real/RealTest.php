<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Real;

use const INF;
use const M_PI;
use const NAN;
use const PHP_FLOAT_MAX;
use const PHP_FLOAT_MIN;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class RealTest extends TestCase
{
    /**
     * @test
     */
    public function create(): Real
    {
        $el = Real::fromString('314.E-2');
        static::assertInstanceOf(Real::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Real $el)
    {
        static::assertEquals(Element::TYPE_REAL, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Real $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): Real
    {
        $el = Real::fromDER($data);
        static::assertInstanceOf(Real::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Real $ref, Real $el)
    {
        static::assertEquals($ref->nr3Val(), $el->nr3Val());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(Real::class, $wrap->asReal());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('REAL expected, got primitive NULL');
        $wrap->asReal();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(Real $el)
    {
        static::assertIsString((string) $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function mantissa(Real $el)
    {
        static::assertEquals(314, $el->mantissa()->toInt());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function exponent(Real $el)
    {
        static::assertEquals(-2, $el->exponent()->toInt());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function base(Real $el)
    {
        static::assertEquals(10, $el->base());
    }

    /**
     * @dataProvider provideFromFloat
     *
     * @test
     */
    public function fromFloat(float $number)
    {
        $real = Real::fromFloat($number);
        $recoded = Real::fromDER($real->toDER());
        static::assertEquals($number, $recoded->floatVal());
    }

    /**
     * @dataProvider provideFromFloat
     *
     * @test
     */
    public function fromFloatNonStrict(float $number)
    {
        $real = Real::fromFloat($number)->withStrictDER(false);
        $recoded = Real::fromDER($real->toDER());
        static::assertEquals($number, $recoded->floatVal());
    }

    public function provideFromFloat(): iterable
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

    /**
     * @test
     */
    public function fromFloatNAN()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NaN values not supported');
        Real::fromFloat(NAN);
    }

    /**
     * @test
     */
    public function fromPartsInvalidBase()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Base must be 2 or 10');
        Real::create(1, 1, 3);
    }

    /**
     * @test
     */
    public function fromNR3()
    {
        $real = Real::fromString('-123,456E-3');
        static::assertEquals(-0.123456, $real->floatVal());
    }

    /**
     * @test
     */
    public function fromNR3Zero()
    {
        $real = Real::fromString('0,0E1');
        static::assertEquals(0.0, $real->floatVal());
    }

    /**
     * @test
     */
    public function fromNR2()
    {
        $real = Real::fromString('-123,456');
        static::assertEquals(-123.456, $real->floatVal());
    }

    /**
     * @test
     */
    public function fromNR2Zero()
    {
        $real = Real::fromString('0,0');
        static::assertEquals(0.0, $real->floatVal());
    }

    /**
     * @test
     */
    public function fromNR1()
    {
        $real = Real::fromString('-123');
        static::assertEquals(-123, $real->floatVal());
    }

    /**
     * @test
     */
    public function fromNR1Zero()
    {
        $real = Real::fromString('0');
        static::assertEquals(0.0, $real->floatVal());
    }

    /**
     * @test
     */
    public function parseNormalize()
    {
        $real = Real::fromString('100');
        static::assertEquals(2, $real->exponent()->toInt());
    }

    /**
     * @test
     */
    public function parseFail()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('X could not be parsed to REAL');
        Real::fromString('X');
    }

    /**
     * @test
     */
    public function base2ToNR3()
    {
        $real = Real::fromFloat(-123.456);
        static::assertEquals('-123456.E-3', $real->nr3Val());
    }

    /**
     * @test
     */
    public function nr3ShiftZeroes()
    {
        $real = Real::create(100, 0, 10);
        static::assertEquals('1.E2', $real->nr3Val());
    }

    /**
     * @test
     */
    public function nr3ZeroExponent()
    {
        $real = Real::create(1, 0, 10);
        static::assertEquals('1.E+0', $real->nr3Val());
    }
}
