<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use Brick\Math\BigInteger;
use Brick\Math\Exception\IntegerOverflowException;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;

/**
 * @internal
 */
final class LengthDecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $length = Length::fromDER("\x0");
        static::assertInstanceOf(Length::class, $length);
    }

    #[Test]
    public function definite()
    {
        $length = Length::fromDER("\x00");
        static::assertFalse($length->isIndefinite());
    }

    #[Test]
    public function indefinite()
    {
        $length = Length::fromDER("\x80");
        static::assertTrue($length->isIndefinite());
    }

    #[Test]
    public function lengthFailsBecauseIndefinite()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Length is indefinite');
        Length::fromDER("\x80")->length();
    }

    #[Test]
    public function intLengthFailsBecauseIndefinite()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Length is indefinite');
        Length::fromDER("\x80")->intLength();
    }

    #[Test]
    public function hugeLengthHasNoIntval()
    {
        $der = "\xfe" . str_repeat("\xff", 126);
        $this->expectException(IntegerOverflowException::class);
        Length::fromDER($der)->intLength();
    }

    #[Test]
    public function shortForm()
    {
        $length = Length::fromDER("\x7f");
        static::assertSame((string) 0x7f, $length->length());
        static::assertSame(0x7f, $length->intLength());
    }

    #[Test]
    public function longForm()
    {
        $length = Length::fromDER("\x81\xff");
        static::assertSame((string) 0xff, $length->length());
    }

    #[Test]
    public function longForm2()
    {
        $length = Length::fromDER("\x82\xca\xfe");
        static::assertSame((string) 0xcafe, $length->length());
        static::assertSame(0xcafe, $length->intLength());
    }

    /**
     * Tests failure when there's too few bytes.
     */
    #[Test]
    public function invalidLongForm()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding long form length');
        Length::fromDER("\x82\xff");
    }

    /**
     * Tests failure when first byte is 0xff.
     */
    #[Test]
    public function invalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid number of length octets');
        Length::fromDER("\xff" . str_repeat("\0", 127));
    }

    #[Test]
    public function hugeLength()
    {
        $der = "\xfe" . str_repeat("\xff", 126);
        $length = Length::fromDER($der);
        $num = BigInteger::fromBase(str_repeat('ff', 126), 16);
        static::assertSame($length->length(), $num->toBase(10));
    }

    #[Test]
    public function offsetFail()
    {
        $offset = 1;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding length');
        Length::fromDER("\x0", $offset);
    }

    #[Test]
    public function expectFail()
    {
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Length 1 overflows data, 0 bytes left');
        Length::expectFromDER("\x01", $offset);
    }

    #[Test]
    public function expectFail2()
    {
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 2, got 1');
        Length::expectFromDER("\x01\x00", $offset, 2);
    }

    #[Test]
    public function expectFailIndefinite()
    {
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 1, got indefinite');
        Length::expectFromDER("\x80", $offset, 1);
    }
}
