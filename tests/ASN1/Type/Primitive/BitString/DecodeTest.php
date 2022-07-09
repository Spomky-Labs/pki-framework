<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\BitString;

use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\BitString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $el = BitString::fromDER("\x3\x2\x0\xff");
        $this->assertInstanceOf(BitString::class, $el);
    }

    /**
     * @test
     */
    public function unusedBits()
    {
        $el = BitString::fromDER("\x3\x3\x4\xff\xf0");
        $this->assertEquals(4, $el->unusedBits());
    }

    /**
     * @test
     */
    public function numBits()
    {
        $el = BitString::fromDER("\x3\x3\x4\xff\xf0");
        $this->assertEquals(12, $el->numBits());
    }

    /**
     * Test that exception is thrown if unused bits are not zero.
     *
     * @test
     */
    public function derPadding()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('DER encoded bit string must have zero padding');
        BitString::fromDER("\x3\x3\x4\xff\xf8");
    }

    /**
     * @test
     */
    public function setBit()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        $this->assertTrue($el->testBit(4));
    }

    /**
     * @test
     */
    public function unsetBit()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        $this->assertFalse($el->testBit(5));
    }

    /**
     * Test that testing unused bit throws an exception.
     *
     * @test
     */
    public function bitFail()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('unused bit');
        $el->testBit(12);
    }

    /**
     * Test that testing out of bounds throws an exception.
     *
     * @test
     */
    public function bitFail2()
    {
        $el = BitString::fromDER("\x3\x3\x4\x08\x00");
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('out of bounds');
        $el->testBit(16);
    }

    /**
     * @test
     */
    public function lengthFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Bit string length must be at least 1');
        BitString::fromDER("\x3\x0");
    }

    /**
     * @test
     */
    public function unusedBitsFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unused bits in a bit string must be less than 8');
        BitString::fromDER("\x3\x3\x8\xff\x00");
    }
}
