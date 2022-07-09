<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Real;

use LogicException;
use PHPUnit\Framework\TestCase;
use RangeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Real;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function longExponent()
    {
        $real = new Real(1, gmp_init('0x40000000'), 2);
        static::assertEquals(hex2bin('090783044000000001'), $real->toDER());
    }

    /**
     * @test
     */
    public function invalidSpecial()
    {
        $real = new Real(0, Real::INF_EXPONENT, 10);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Invalid special value');
        $real->toDER();
    }

    /**
     * @test
     */
    public function mantissaNormalization()
    {
        $real = new Real(8, 0, 2);
        static::assertEquals(hex2bin('0903800301'), $real->toDER());
        static::assertEquals(8.0, Real::fromDER($real->toDER())->floatVal());
    }

    /**
     * @test
     */
    public function mantissaNormalizationBase8()
    {
        $real = (new Real(8, 3, 2))->withStrictDER(false);
        static::assertEquals(hex2bin('0903900201'), $real->toDER());
        static::assertEquals(64.0, Real::fromDER($real->toDER())->floatVal());
    }

    /**
     * @test
     */
    public function mantissaNormalizationBase16()
    {
        $real = (new Real(16, 4, 2))->withStrictDER(false);
        static::assertEquals(hex2bin('0903A00201'), $real->toDER());
        static::assertEquals(256.0, Real::fromDER($real->toDER())->floatVal());
    }

    /**
     * @test
     */
    public function scaleFactor()
    {
        $real = (new Real(128, 4, 2))->withStrictDER(false);
        static::assertEquals(hex2bin('0903AC0201'), $real->toDER());
        static::assertEquals(2048.0, Real::fromDER($real->toDER())->floatVal());
    }

    /**
     * @test
     */
    public function veryLongExponent()
    {
        $real = new Real(1, gmp_init('0x40' . str_repeat('00', 254)), 2);
        $expected = hex2bin('0982010283ff40' . str_repeat('00', 254) . '01');
        static::assertEquals($expected, $real->toDER());
    }

    /**
     * @test
     */
    public function tooLongExponent()
    {
        $real = new Real(1, gmp_init('0x40' . str_repeat('00', 255)), 2);
        $this->expectException(RangeException::class);
        $this->expectExceptionMessage('Exponent encoding is too long');
        $real->toDER();
    }
}
