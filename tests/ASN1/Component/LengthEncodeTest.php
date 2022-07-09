<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Component;

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
        $largenum = gmp_init(str_repeat('ff', 126), 16);
        $length = new Length(gmp_strval($largenum, 10));
        $expected = "\xfe" . str_repeat("\xff", 126);
        static::assertEquals($expected, $length->toDER());
    }

    /**
     * @test
     */
    public function tooLong()
    {
        $largenum = gmp_init(str_repeat('ff', 127), 16);
        $length = new Length(gmp_strval($largenum, 10));
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Too many length octets');
        $length->toDER();
    }

    /**
     * @test
     */
    public function tooLong2()
    {
        $largenum = gmp_init(str_repeat('ff', 128), 16);
        $length = new Length(gmp_strval($largenum, 10));
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Too many length octets');
        $length->toDER();
    }
}
