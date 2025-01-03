<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Integer;

use Brick\Math\BigInteger;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use function chr;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function zero()
    {
        $int = Integer::create(0);
        static::assertSame("\x2\x1\x0", $int->toDER());
    }

    #[Test]
    public function negativeZero()
    {
        $int = Integer::create('-0');
        static::assertSame("\x2\x1\x0", $int->toDER());
    }

    #[Test]
    public function invalidNumber()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not a valid number');
        Integer::create('one');
    }

    #[Test]
    public function empty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not a valid number');
        Integer::create('');
    }

    #[Test]
    public function positive127()
    {
        $int = Integer::create(127);
        static::assertSame("\x2\x1\x7f", $int->toDER());
    }

    #[Test]
    public function positive128()
    {
        $int = Integer::create(128);
        static::assertSame("\x2\x2\x0\x80", $int->toDER());
    }

    #[Test]
    public function positive255()
    {
        $int = Integer::create(255);
        static::assertSame("\x2\x2\x0\xff", $int->toDER());
    }

    #[Test]
    public function positive256()
    {
        $int = Integer::create(256);
        static::assertSame("\x2\x2\x01\x00", $int->toDER());
    }

    #[Test]
    public function positive32767()
    {
        $int = Integer::create(32767);
        static::assertSame("\x2\x2\x7f\xff", $int->toDER());
    }

    #[Test]
    public function positive32768()
    {
        $int = Integer::create(32768);
        static::assertSame("\x2\x3\x0\x80\x00", $int->toDER());
    }

    #[Test]
    public function negative1()
    {
        $int = Integer::create(-1);
        $der = "\x2\x1" . chr(0b11111111);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative2()
    {
        $int = Integer::create(-2);
        $der = "\x2\x1" . chr(0b11111110);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative127()
    {
        $int = Integer::create(-127);
        $der = "\x2\x1" . chr(0b10000001);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative128()
    {
        $int = Integer::create(-128);
        $der = "\x2\x1" . chr(0b10000000);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative129()
    {
        $int = Integer::create(-129);
        $der = "\x2\x2" . chr(0b11111111) . chr(0b01111111);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative255()
    {
        $int = Integer::create(-255);
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000001);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative256()
    {
        $int = Integer::create(-256);
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000000);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative257()
    {
        $int = Integer::create(-257);
        $der = "\x2\x2" . chr(0b11111110) . chr(0b11111111);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative32767()
    {
        $int = Integer::create(-32767);
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000001);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative32768()
    {
        $int = Integer::create(-32768);
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000000);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative32769()
    {
        $int = Integer::create(-32769);
        $der = "\x2\x3" . chr(0b11111111) . chr(0b01111111) . chr(0b11111111);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative65535()
    {
        $int = Integer::create(-65535);
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000001);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative65536()
    {
        $int = Integer::create(-65536);
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000000);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function negative65537()
    {
        $int = Integer::create(-65537);
        $der = "\x2\x3" . chr(0b11111110) . chr(0b11111111) . chr(0b11111111);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function hugePositive()
    {
        $num = BigInteger::fromBase('7f' . str_repeat('ff', 0xfffe), 16);
        $int = Integer::create($num);
        $der = "\x2\x82\xff\xff\x7f" . str_repeat("\xff", 0xfffe);
        static::assertSame($der, $int->toDER());
    }

    #[Test]
    public function hugeNegative()
    {
        $num = BigInteger::of(0)->minus(BigInteger::fromBase('80' . str_repeat('00', 0xfffe), 16));
        $int = Integer::create($num);
        $der = "\x2\x82\xff\xff\x80" . str_repeat("\x00", 0xfffe);
        static::assertSame($der, $int->toDER());
    }
}
