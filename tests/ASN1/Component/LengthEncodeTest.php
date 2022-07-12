<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

use Brick\Math\BigInteger;
use DomainException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Length;

/**
 * @internal
 */
final class LengthEncodeTest extends TestCase
{
    /**
     * @test
     */
    public function definite()
    {
        $length = new Length(0, false);
        static::assertEquals("\x0", $length->toDER());
    }

    /**
     * @test
     */
    public function indefinite()
    {
        $length = new Length(0, true);
        static::assertEquals("\x80", $length->toDER());
    }

    /**
     * @test
     */
    public function short()
    {
        $length = new Length(0x7f);
        static::assertEquals("\x7f", $length->toDER());
    }

    /**
     * @test
     */
    public function long()
    {
        $length = new Length(0xff);
        static::assertEquals("\x81\xff", $length->toDER());
    }

    /**
     * @test
     */
    public function long2()
    {
        $length = new Length(0xcafe);
        static::assertEquals("\x82\xca\xfe", $length->toDER());
    }

    /**
     * @test
     */
    public function hugeLength()
    {
        $largenum = BigInteger::fromBase(str_repeat('ff', 126), 16);
        $length = new Length($largenum);
        $expected = "\xfe" . str_repeat("\xff", 126);
        static::assertEquals($expected, $length->toDER());
    }

    /**
     * @test
     */
    public function tooLong()
    {
        $largenum = BigInteger::fromBase(str_repeat('ff', 127), 16);
        $length = new Length($largenum);
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Too many length octets');
        $length->toDER();
    }

    /**
     * @test
     */
    public function tooLong2()
    {
        $largenum = BigInteger::fromBase(str_repeat('ff', 128), 16);
        $length = new Length($largenum);
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Too many length octets');
        $length->toDER();
    }
}
