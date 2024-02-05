<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\BitString;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    #[DataProvider('withoutTrailingZeroesProvider')]
    public function withoutTrailingZeroes(string $bits, string $expected)
    {
        $bs = BitString::create($bits);
        static::assertSame($expected, $bs->withoutTrailingZeroes()->toDER());
    }

    public static function withoutTrailingZeroesProvider(): Iterator
    {
        yield ['', "\x3\x1\x0"];
        yield ["\x00", "\x3\x1\x0"];
        yield ["\x80", "\x3\x2\x7\x80"];
        yield ["\xf0", "\x3\x2\x4\xf0"];
        yield ["\xfe", "\x3\x2\x1\xfe"];
        yield ["\xff", "\x3\x2\x0\xff"];
        yield ["\xff\xff\xf0", "\x3\x4\x4\xff\xff\xf0"];
        yield ["\xff\xf0\x00", "\x3\x3\x4\xff\xf0"];
        yield ["\xf0\x00\x00", "\x3\x2\x4\xf0"];
        yield ["\x00\x00\x00", "\x3\x1\x0"];
        yield ["\x00\x00\x02", "\x3\x4\x1\x0\x0\x02"];
        yield ["\x00\x02\x00", "\x3\x3\x1\x0\x02"];
        yield ["\x00\x01\x00", "\x3\x3\x0\x0\x01"];
        yield ["\x00\x80\x00", "\x3\x3\x7\x0\x80"];
    }
}
