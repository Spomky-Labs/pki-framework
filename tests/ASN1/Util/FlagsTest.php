<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Util;

use Brick\Math\BigInteger;
use OutOfBoundsException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Util\Flags;

/**
 * @internal
 */
final class FlagsTest extends TestCase
{
    #[Test]
    #[DataProvider('flagsProvider')]
    public function flags(BigInteger|int|string $num, int $width, string $result)
    {
        $flags = Flags::create($num, $width);
        static::assertEquals($result, $flags->string());
    }

    public static function flagsProvider(): array
    {
        return [
            [1, 0, ''],
            [1, 1, "\x80"],
            [1, 4, "\x10"],
            [1, 6, "\x04"],
            [1, 8, "\x01"],
            [1, 12, "\x00\x10"],
            [1, 16, "\x00\x01"],
            [0, 8, "\x00"],
            [0, 9, "\x00\x00"],
            [0xff, 8, "\xff"],
            [0xff, 4, "\xf0"],
            [0xff, 1, "\x80"],
            [0xffff, 1, "\x80"],
            [0xffffff, 12, "\xff\xf0"],
            [1, 128, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"],
            [BigInteger::fromBase('80000000000000000000000000000000', 16), 128, "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"],
        ];
    }

    #[Test]
    #[DataProvider('setBitProvider')]
    public function setBit(int $num, int $width, int $idx)
    {
        $flags = Flags::create($num, $width);
        static::assertTrue($flags->test($idx));
    }

    public static function setBitProvider(): array
    {
        return [
            [1, 1, 0],
            [1, 4, 3],
            [1, 8, 7],
            [1, 16, 15],
            [1, 128, 127],
            [0x08, 4, 0],
            [0x80, 8, 0],
            [0x8000, 16, 0],
            [0x80, 16, 8],
        ];
    }

    #[Test]
    #[DataProvider('unsetBitProvider')]
    public function unsetBit(int $num, int $width, int $idx)
    {
        $flags = Flags::create($num, $width);
        static::assertFalse($flags->test($idx));
    }

    public static function unsetBitProvider(): array
    {
        return [[0x7f, 8, 0], [0xfe, 8, 7], [0xff7f, 8, 0], [0xff7f, 12, 4], [0xff7f, 16, 8]];
    }

    /**
     * @param string $result
     */
    #[Test]
    #[DataProvider('toBitStringProvider')]
    public function toBitString(int $num, int $width, $result, int $unused_bits)
    {
        $flags = Flags::create($num, $width);
        $bs = $flags->bitString();
        static::assertEquals($result, $bs->string());
        static::assertEquals($unused_bits, $bs->unusedBits());
    }

    public static function toBitStringProvider(): array
    {
        return [
            [0, 0, '', 0],
            [1, 1, "\x80", 7],
            [1, 4, "\x10", 4],
            [1, 8, "\x01", 0],
            [1, 12, "\x0\x10", 4],
            [1, 16, "\x0\x01", 0],
            [0, 16, "\x0\x0", 0],
            [0x800, 12, "\x80\x0", 4],
            [0x8000, 16, "\x80\x0", 0],
        ];
    }

    #[Test]
    #[DataProvider('fromBitStringProvider')]
    public function fromBitString(string $str, int $unused_bits, int $width, string $result)
    {
        $flags = Flags::fromBitString(BitString::create($str, $unused_bits), $width);
        static::assertEquals($result, $flags->string());
    }

    public static function fromBitStringProvider(): array
    {
        return [
            ["\xff", 0, 8, "\xff"],
            ["\xff", 0, 4, "\xf0"],
            ['', 0, 8, "\x00"],
            ["\xff\xff", 4, 16, "\xff\xf0"],
            ["\xff\x80", 7, 16, "\xff\x80"],
            ["\x00\x10", 4, 12, "\x00\x10"],
            ["\x00\x10", 4, 24, "\x00\x10\x00"],
        ];
    }

    /**
     * @param number $result
     */
    #[Test]
    #[DataProvider('numberProvider')]
    public function number(BigInteger|int|string $num, int $width, $result)
    {
        $flags = Flags::create($num, $width);
        static::assertEquals($result, $flags->number());
    }

    public static function numberProvider(): array
    {
        return [
            [0xff, 8, 255],
            [0xff, 4, 15],
            [0xff, 2, 3],
            [0xff, 1, 1],
            [0, 8, 0],
            [1, 1, 1],
            [1, 4, 1],
            [1, 8, 1],
            [1, 12, 1],
            [1, 16, 1],
            [0x80, 24, 0x80],
            [0x8000, 16, 0x8000],
            [
                BigInteger::fromBase('080000000000000000000000000000000', 16),
                128,
                '170141183460469231731687303715884105728',
            ],
        ];
    }

    /**
     * @param string $str
     * @param number $number
     */
    #[Test]
    #[DataProvider('bitStringToNumberProvider')]
    public function bitStringToNumber($str, int $unused_bits, int $width, $number)
    {
        $bs = BitString::create($str, $unused_bits);
        $flags = Flags::fromBitString($bs, $width);
        static::assertEquals($number, $flags->number());
    }

    public static function bitStringToNumberProvider(): array
    {
        return [["\x20", 5, 9, 64]];
    }

    #[Test]
    public function intNumber()
    {
        $flags = Flags::create(0x80, 16);
        static::assertSame($flags->intNumber(), 128);
    }

    #[Test]
    /**
     * @test
     */
    public function oOB()
    {
        $flags = Flags::create(0, 8);
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Index is out of bounds');
        $flags->test(8);
    }
}
