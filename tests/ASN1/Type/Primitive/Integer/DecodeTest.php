<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Integer;

use Brick\Math\BigInteger;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use function chr;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = Integer::fromDER("\x2\x1\x00");
        static::assertInstanceOf(Integer::class, $el);
    }

    #[Test]
    public function zero()
    {
        $der = "\x2\x1\x0";
        static::assertSame((string) 0, Integer::fromDER($der)->number());
    }

    #[Test]
    public function positive127()
    {
        $der = "\x2\x1\x7f";
        static::assertSame((string) 127, Integer::fromDER($der)->number());
    }

    #[Test]
    public function positive128()
    {
        $der = "\x2\x2\x0\x80";
        static::assertSame((string) 128, Integer::fromDER($der)->number());
    }

    #[Test]
    public function positive255()
    {
        $der = "\x2\x2\x0\xff";
        static::assertSame((string) 255, Integer::fromDER($der)->number());
    }

    #[Test]
    public function positive256()
    {
        $der = "\x2\x2\x01\x00";
        static::assertSame((string) 256, Integer::fromDER($der)->number());
    }

    #[Test]
    public function positive32767()
    {
        $der = "\x2\x2\x7f\xff";
        static::assertSame((string) 32767, Integer::fromDER($der)->number());
    }

    #[Test]
    public function positive32768()
    {
        $der = "\x2\x3\x0\x80\x00";
        static::assertSame((string) 32768, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative1()
    {
        $der = "\x2\x1" . chr(0b11111111);
        static::assertSame((string) -1, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative2()
    {
        $der = "\x2\x1" . chr(0b11111110);
        static::assertSame((string) -2, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative127()
    {
        $der = "\x2\x1" . chr(0b10000001);
        static::assertSame((string) -127, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative128()
    {
        $der = "\x2\x1" . chr(0b10000000);
        static::assertSame((string) -128, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative129()
    {
        $der = "\x2\x2" . chr(0b11111111) . chr(0b01111111);
        static::assertSame((string) -129, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative255()
    {
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000001);
        static::assertSame((string) -255, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative256()
    {
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000000);
        static::assertSame((string) -256, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative257()
    {
        $der = "\x2\x2" . chr(0b11111110) . chr(0b11111111);
        static::assertSame((string) -257, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative32767()
    {
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000001);
        static::assertSame((string) -32767, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative32768()
    {
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000000);
        static::assertSame((string) -32768, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative32769()
    {
        $der = "\x2\x3" . chr(0b11111111) . chr(0b01111111) . chr(0b11111111);
        static::assertSame((string) -32769, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative65535()
    {
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000001);
        static::assertSame((string) -65535, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative65536()
    {
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000000);
        static::assertSame((string) -65536, Integer::fromDER($der)->number());
    }

    #[Test]
    public function negative65537()
    {
        $der = "\x2\x3" . chr(0b11111110) . chr(0b11111111) . chr(0b11111111);
        static::assertSame((string) -65537, Integer::fromDER($der)->number());
    }

    #[Test]
    public function invalidLength()
    {
        $der = "\x2\x2\x0";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Length 2 overflows data, 1 bytes left');
        Integer::fromDER($der);
    }

    #[Test]
    public function hugePositive()
    {
        $der = "\x2\x82\xff\xff\x7f" . str_repeat("\xff", 0xfffe);
        $num = BigInteger::fromBase('7f' . str_repeat('ff', 0xfffe), 16);
        static::assertSame($num->toBase(10), Integer::fromDER($der)->number());
    }

    #[Test]
    public function hugeNegative()
    {
        $der = "\x2\x82\xff\xff\x80" . str_repeat("\x00", 0xfffe);
        $num = BigInteger::of(0)->minus(BigInteger::fromBase('80' . str_repeat('00', 0xfffe), 16));
        static::assertSame($num->toBase(10), Integer::fromDER($der)->number());
    }
}
