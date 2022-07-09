<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Real;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\Real;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @internal
 */
final class RealTest extends TestCase
{
    public function testCreate(): Real
    {
        $el = Real::fromString('314.E-2');
        $this->assertInstanceOf(Real::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testTag(Real $el)
    {
        $this->assertEquals(Element::TYPE_REAL, $el->tag());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Real $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     */
    public function testDecode(string $data): Real
    {
        $el = Real::fromDER($data);
        $this->assertInstanceOf(Real::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Real $ref, Real $el)
    {
        $this->assertEquals($ref->nr3Val(), $el->nr3Val());
    }

    /**
     * @depends testCreate
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(Real::class, $wrap->asReal());
    }

    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('REAL expected, got primitive NULL');
        $wrap->asReal();
    }

    /**
     * @depends testCreate
     */
    public function testString(Real $el)
    {
        $this->assertIsString((string) $el);
    }

    /**
     * @depends testCreate
     */
    public function testMantissa(Real $el)
    {
        $this->assertEquals(314, $el->mantissa()->intVal());
    }

    /**
     * @depends testCreate
     */
    public function testExponent(Real $el)
    {
        $this->assertEquals(-2, $el->exponent()->intVal());
    }

    /**
     * @depends testCreate
     */
    public function testBase(Real $el)
    {
        $this->assertEquals(10, $el->base());
    }

    /**
     * @dataProvider provideFromFloat
     */
    public function testFromFloat(float $number)
    {
        $real = Real::fromFloat($number);
        $recoded = Real::fromDER($real->toDER());
        $this->assertEquals($number, $recoded->floatVal());
    }

    /**
     * @dataProvider provideFromFloat
     */
    public function testFromFloatNonStrict(float $number)
    {
        $real = Real::fromFloat($number)->withStrictDER(false);
        $recoded = Real::fromDER($real->toDER());
        $this->assertEquals($number, $recoded->floatVal());
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

    public function testFromFloatNAN()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('NaN values not supported');
        Real::fromFloat(NAN);
    }

    public function testFromPartsInvalidBase()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Base must be 2 or 10');
        new Real(1, 1, 3);
    }

    public function testFromNR3()
    {
        $real = Real::fromString('-123,456E-3');
        $this->assertEquals(-0.123456, $real->floatVal());
    }

    public function testFromNR3Zero()
    {
        $real = Real::fromString('0,0E1');
        $this->assertEquals(0.0, $real->floatVal());
    }

    public function testFromNR2()
    {
        $real = Real::fromString('-123,456');
        $this->assertEquals(-123.456, $real->floatVal());
    }

    public function testFromNR2Zero()
    {
        $real = Real::fromString('0,0');
        $this->assertEquals(0.0, $real->floatVal());
    }

    public function testFromNR1()
    {
        $real = Real::fromString('-123');
        $this->assertEquals(-123, $real->floatVal());
    }

    public function testFromNR1Zero()
    {
        $real = Real::fromString('0');
        $this->assertEquals(0.0, $real->floatVal());
    }

    public function testParseNormalize()
    {
        $real = Real::fromString('100');
        $this->assertEquals(2, $real->exponent()->intVal());
    }

    public function testParseFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('X could not be parsed to REAL');
        Real::fromString('X');
    }

    public function testBase2ToNR3()
    {
        $real = Real::fromFloat(-123.456);
        $this->assertEquals('-123456.E-3', $real->nr3Val());
    }

    public function testNr3ShiftZeroes()
    {
        $real = new Real(100, 0, 10);
        $this->assertEquals('1.E2', $real->nr3Val());
    }

    public function testNr3ZeroExponent()
    {
        $real = new Real(1, 0, 10);
        $this->assertEquals('1.E+0', $real->nr3Val());
    }
}
