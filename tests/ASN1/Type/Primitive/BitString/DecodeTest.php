<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\BitString;

use OutOfBoundsException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = BitString::fromDER("\x3\x2\x0\xff");
        static::assertInstanceOf(BitString::class, $el);
    }

    #[Test]
    public function unusedBits()
    {
        $el = BitString::fromDER("\x3\x3\x4\xff\xf0");
        static::assertSame(4, $el->unusedBits());
    }

    #[Test]
    public function numBits()
    {
        $el = BitString::fromDER("\x3\x3\x4\xff\xf0");
        static::assertSame(12, $el->numBits());
    }

    /**
     * Test that exception is thrown if unused bits are not zero.
     */
    #[Test]
    public function derPadding()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('DER encoded bit string must have zero padding');
        BitString::fromDER("\x3\x3\x4\xff\xf8");
    }

    #[Test]
    public function setBit()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        static::assertTrue($el->testBit(4));
    }

    #[Test]
    public function unsetBit()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        static::assertFalse($el->testBit(5));
    }

    /**
     * Test that testing unused bit throws an exception.
     */
    #[Test]
    public function bitFail()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('unused bit');
        $el->testBit(12);
    }

    /**
     * Test that testing out of bounds throws an exception.
     */
    #[Test]
    public function bitFail2()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('out of bounds');
        $el->testBit(16);
    }

    #[Test]
    public function lengthFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Bit string length must be at least 1');
        BitString::fromDER("\x3\x0");
    }

    #[Test]
    public function unusedBitsFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unused bits in a bit string must be less than 8');
        BitString::fromDER("\x3\x3\x8\xff\x00");
    }
}
