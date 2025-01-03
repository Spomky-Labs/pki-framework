<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Util;

use Brick\Math\BigInteger;
use Iterator;
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
        static::assertSame($result, $flags->string());
    }

    public static function flagsProvider(): Iterator
    {
        yield [1, 0, ''];
        yield [1, 1, "\x80"];
        yield [1, 4, "\x10"];
        yield [1, 6, "\x04"];
        yield [1, 8, "\x01"];
        yield [1, 12, "\x00\x10"];
        yield [1, 16, "\x00\x01"];
        yield [0, 8, "\x00"];
        yield [0, 9, "\x00\x00"];
        yield [0xff, 8, "\xff"];
        yield [0xff, 4, "\xf0"];
        yield [0xff, 1, "\x80"];
        yield [0xffff, 1, "\x80"];
        yield [0xffffff, 12, "\xff\xf0"];
        yield [1, 128, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"];
        yield [BigInteger::fromBase('80000000000000000000000000000000', 16), 128, "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"];
    }

    #[Test]
    #[DataProvider('setBitProvider')]
    public function setBit(int $num, int $width, int $idx)
    {
        $flags = Flags::create($num, $width);
        static::assertTrue($flags->test($idx));
    }

    public static function setBitProvider(): Iterator
    {
        yield [1, 1, 0];
        yield [1, 4, 3];
        yield [1, 8, 7];
        yield [1, 16, 15];
        yield [1, 128, 127];
        yield [0x08, 4, 0];
        yield [0x80, 8, 0];
        yield [0x8000, 16, 0];
        yield [0x80, 16, 8];
    }

    #[Test]
    #[DataProvider('unsetBitProvider')]
    public function unsetBit(int $num, int $width, int $idx)
    {
        $flags = Flags::create($num, $width);
        static::assertFalse($flags->test($idx));
    }

    public static function unsetBitProvider(): Iterator
    {
        yield [0x7f, 8, 0];
        yield [0xfe, 8, 7];
        yield [0xff7f, 8, 0];
        yield [0xff7f, 12, 4];
        yield [0xff7f, 16, 8];
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
        static::assertSame($result, $bs->string());
        static::assertSame($unused_bits, $bs->unusedBits());
    }

    public static function toBitStringProvider(): Iterator
    {
        yield [0, 0, '', 0];
        yield [1, 1, "\x80", 7];
        yield [1, 4, "\x10", 4];
        yield [1, 8, "\x01", 0];
        yield [1, 12, "\x0\x10", 4];
        yield [1, 16, "\x0\x01", 0];
        yield [0, 16, "\x0\x0", 0];
        yield [0x800, 12, "\x80\x0", 4];
        yield [0x8000, 16, "\x80\x0", 0];
    }

    #[Test]
    #[DataProvider('fromBitStringProvider')]
    public function fromBitString(string $str, int $unused_bits, int $width, string $result)
    {
        $flags = Flags::fromBitString(BitString::create($str, $unused_bits), $width);
        static::assertSame($result, $flags->string());
    }

    public static function fromBitStringProvider(): Iterator
    {
        yield ["\xff", 0, 8, "\xff"];
        yield ["\xff", 0, 4, "\xf0"];
        yield ['', 0, 8, "\x00"];
        yield ["\xff\xff", 4, 16, "\xff\xf0"];
        yield ["\xff\x80", 7, 16, "\xff\x80"];
        yield ["\x00\x10", 4, 12, "\x00\x10"];
        yield ["\x00\x10", 4, 24, "\x00\x10\x00"];
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

    public static function numberProvider(): Iterator
    {
        yield [0xff, 8, 255];
        yield [0xff, 4, 15];
        yield [0xff, 2, 3];
        yield [0xff, 1, 1];
        yield [0, 8, 0];
        yield [1, 1, 1];
        yield [1, 4, 1];
        yield [1, 8, 1];
        yield [1, 12, 1];
        yield [1, 16, 1];
        yield [0x80, 24, 0x80];
        yield [0x8000, 16, 0x8000];
        yield [
            BigInteger::fromBase('080000000000000000000000000000000', 16),
            128,
            '170141183460469231731687303715884105728',
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

    public static function bitStringToNumberProvider(): Iterator
    {
        yield ["\x20", 5, 9, 64];
    }

    #[Test]
    public function intNumber()
    {
        $flags = Flags::create(0x80, 16);
        static::assertSame(128, $flags->intNumber());
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
