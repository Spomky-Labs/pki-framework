<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Integer;

use function chr;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\Integer;

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
        $el = Integer::fromDER("\x2\x1\x00");
        $this->assertInstanceOf(Integer::class, $el);
    }

    /**
     * @test
     */
    public function zero()
    {
        $der = "\x2\x1\x0";
        $this->assertEquals(0, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function positive127()
    {
        $der = "\x2\x1\x7f";
        $this->assertEquals(127, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function positive128()
    {
        $der = "\x2\x2\x0\x80";
        $this->assertEquals(128, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function positive255()
    {
        $der = "\x2\x2\x0\xff";
        $this->assertEquals(255, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function positive256()
    {
        $der = "\x2\x2\x01\x00";
        $this->assertEquals(256, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function positive32767()
    {
        $der = "\x2\x2\x7f\xff";
        $this->assertEquals(32767, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function positive32768()
    {
        $der = "\x2\x3\x0\x80\x00";
        $this->assertEquals(32768, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative1()
    {
        $der = "\x2\x1" . chr(0b11111111);
        $this->assertEquals(-1, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative2()
    {
        $der = "\x2\x1" . chr(0b11111110);
        $this->assertEquals(-2, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative127()
    {
        $der = "\x2\x1" . chr(0b10000001);
        $this->assertEquals(-127, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative128()
    {
        $der = "\x2\x1" . chr(0b10000000);
        $this->assertEquals(-128, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative129()
    {
        $der = "\x2\x2" . chr(0b11111111) . chr(0b01111111);
        $this->assertEquals(-129, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative255()
    {
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000001);
        $this->assertEquals(-255, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative256()
    {
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000000);
        $this->assertEquals(-256, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative257()
    {
        $der = "\x2\x2" . chr(0b11111110) . chr(0b11111111);
        $this->assertEquals(-257, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative32767()
    {
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000001);
        $this->assertEquals(-32767, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative32768()
    {
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000000);
        $this->assertEquals(-32768, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative32769()
    {
        $der = "\x2\x3" . chr(0b11111111) . chr(0b01111111) . chr(0b11111111);
        $this->assertEquals(-32769, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative65535()
    {
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000001);
        $this->assertEquals(-65535, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative65536()
    {
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000000);
        $this->assertEquals(-65536, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function negative65537()
    {
        $der = "\x2\x3" . chr(0b11111110) . chr(0b11111111) . chr(0b11111111);
        $this->assertEquals(-65537, Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function invalidLength()
    {
        $der = "\x2\x2\x0";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Length 2 overflows data, 1 bytes left');
        Integer::fromDER($der);
    }

    /**
     * @test
     */
    public function hugePositive()
    {
        $der = "\x2\x82\xff\xff\x7f" . str_repeat("\xff", 0xfffe);
        $num = gmp_init('7f' . str_repeat('ff', 0xfffe), 16);
        $this->assertEquals(gmp_strval($num), Integer::fromDER($der)->number());
    }

    /**
     * @test
     */
    public function hugeNegative()
    {
        $der = "\x2\x82\xff\xff\x80" . str_repeat("\x00", 0xfffe);
        $num = 0 - gmp_init('80' . str_repeat('00', 0xfffe), 16);
        $this->assertEquals(gmp_strval($num), Integer::fromDER($der)->number());
    }
}
