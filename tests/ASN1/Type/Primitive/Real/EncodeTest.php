<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Real;

use Brick\Math\BigInteger;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RangeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function longExponent()
    {
        $real = Real::create(1, BigInteger::fromBase('40000000', 16), 2);
        static::assertEquals(hex2bin('090783044000000001'), $real->toDER());
    }

    #[Test]
    public function invalidSpecial()
    {
        $real = Real::create(0, Real::INF_EXPONENT, 10);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Invalid special value');
        $real->toDER();
    }

    #[Test]
    public function mantissaNormalization()
    {
        $real = Real::create(8, 0, 2);
        static::assertEquals(hex2bin('0903800301'), $real->toDER());
        static::assertSame(8.0, Real::fromDER($real->toDER())->floatVal());
    }

    #[Test]
    public function mantissaNormalizationBase8()
    {
        $real = (Real::create(8, 3, 2))->withStrictDER(false);
        static::assertEquals(hex2bin('0903900201'), $real->toDER());
        static::assertSame(64.0, Real::fromDER($real->toDER())->floatVal());
    }

    #[Test]
    public function mantissaNormalizationBase16()
    {
        $real = (Real::create(16, 4, 2))->withStrictDER(false);
        static::assertEquals(hex2bin('0903A00201'), $real->toDER());
        static::assertSame(256.0, Real::fromDER($real->toDER())->floatVal());
    }

    #[Test]
    public function scaleFactor()
    {
        $real = (Real::create(128, 4, 2))->withStrictDER(false);
        static::assertEquals(hex2bin('0903AC0201'), $real->toDER());
        static::assertSame(2048.0, Real::fromDER($real->toDER())->floatVal());
    }

    #[Test]
    public function veryLongExponent()
    {
        $real = Real::create(1, BigInteger::fromBase('40' . str_repeat('00', 254), 16), 2);
        $expected = hex2bin('0982010283ff40' . str_repeat('00', 254) . '01');
        static::assertEquals($expected, $real->toDER());
    }

    #[Test]
    public function tooLongExponent()
    {
        $real = Real::create(1, BigInteger::fromBase('40' . str_repeat('00', 255), 16), 2);
        $this->expectException(RangeException::class);
        $this->expectExceptionMessage('Exponent encoding is too long');
        $real->toDER();
    }
}
