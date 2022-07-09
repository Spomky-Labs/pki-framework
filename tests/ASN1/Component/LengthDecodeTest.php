<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Component;

use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Component\Length;
use Sop\ASN1\Exception\DecodeException;

/**
 * @internal
 */
final class LengthDecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $length = Length::fromDER("\x0");
        static::assertInstanceOf(Length::class, $length);
    }

    /**
     * @test
     */
    public function definite()
    {
        $length = Length::fromDER("\x00");
        static::assertFalse($length->isIndefinite());
    }

    /**
     * @test
     */
    public function indefinite()
    {
        $length = Length::fromDER("\x80");
        static::assertTrue($length->isIndefinite());
    }

    /**
     * @test
     */
    public function lengthFailsBecauseIndefinite()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Length is indefinite');
        Length::fromDER("\x80")->length();
    }

    /**
     * @test
     */
    public function intLengthFailsBecauseIndefinite()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Length is indefinite');
        Length::fromDER("\x80")->intLength();
    }

    /**
     * @test
     */
    public function hugeLengthHasNoIntval()
    {
        $der = "\xfe" . str_repeat("\xff", 126);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Integer overflow');
        Length::fromDER($der)->intLength();
    }

    /**
     * @test
     */
    public function shortForm()
    {
        $length = Length::fromDER("\x7f");
        static::assertEquals(0x7f, $length->length());
        static::assertEquals(0x7f, $length->intLength());
    }

    /**
     * @test
     */
    public function longForm()
    {
        $length = Length::fromDER("\x81\xff");
        static::assertEquals(0xff, $length->length());
    }

    /**
     * @test
     */
    public function longForm2()
    {
        $length = Length::fromDER("\x82\xca\xfe");
        static::assertEquals(0xcafe, $length->length());
        static::assertEquals(0xcafe, $length->intLength());
    }

    /**
     * Tests failure when there's too few bytes.
     *
     * @test
     */
    public function invalidLongForm()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding long form length');
        Length::fromDER("\x82\xff");
    }

    /**
     * Tests failure when first byte is 0xff.
     *
     * @test
     */
    public function invalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Invalid number of length octets');
        Length::fromDER("\xff" . str_repeat("\0", 127));
    }

    /**
     * @test
     */
    public function hugeLength()
    {
        $der = "\xfe" . str_repeat("\xff", 126);
        $length = Length::fromDER($der);
        $num = gmp_init(str_repeat('ff', 126), 16);
        static::assertEquals($length->length(), gmp_strval($num));
    }

    /**
     * @test
     */
    public function offsetFail()
    {
        $offset = 1;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data while decoding length');
        Length::fromDER("\x0", $offset);
    }

    /**
     * @test
     */
    public function expectFail()
    {
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Length 1 overflows data, 0 bytes left');
        Length::expectFromDER("\x01", $offset);
    }

    /**
     * @test
     */
    public function expectFail2()
    {
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 2, got 1');
        Length::expectFromDER("\x01\x00", $offset, 2);
    }

    /**
     * @test
     */
    public function expectFailIndefinite()
    {
        $offset = 0;
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 1, got indefinite');
        Length::expectFromDER("\x80", $offset, 1);
    }
}
