<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Integer;

use function chr;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\Integer;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function zero()
    {
        $int = new Integer(0);
        $this->assertEquals("\x2\x1\x0", $int->toDER());
    }

    /**
     * @test
     */
    public function negativeZero()
    {
        $int = new Integer('-0');
        $this->assertEquals("\x2\x1\x0", $int->toDER());
    }

    /**
     * @test
     */
    public function invalidNumber()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not a valid number');
        new Integer('one');
    }

    /**
     * @test
     */
    public function empty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not a valid number');
        new Integer('');
    }

    /**
     * @test
     */
    public function positive127()
    {
        $int = new Integer(127);
        $this->assertEquals("\x2\x1\x7f", $int->toDER());
    }

    /**
     * @test
     */
    public function positive128()
    {
        $int = new Integer(128);
        $this->assertEquals("\x2\x2\x0\x80", $int->toDER());
    }

    /**
     * @test
     */
    public function positive255()
    {
        $int = new Integer(255);
        $this->assertEquals("\x2\x2\x0\xff", $int->toDER());
    }

    /**
     * @test
     */
    public function positive256()
    {
        $int = new Integer(256);
        $this->assertEquals("\x2\x2\x01\x00", $int->toDER());
    }

    /**
     * @test
     */
    public function positive32767()
    {
        $int = new Integer(32767);
        $this->assertEquals("\x2\x2\x7f\xff", $int->toDER());
    }

    /**
     * @test
     */
    public function positive32768()
    {
        $int = new Integer(32768);
        $this->assertEquals("\x2\x3\x0\x80\x00", $int->toDER());
    }

    /**
     * @test
     */
    public function negative1()
    {
        $int = new Integer(-1);
        $der = "\x2\x1" . chr(0b11111111);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative2()
    {
        $int = new Integer(-2);
        $der = "\x2\x1" . chr(0b11111110);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative127()
    {
        $int = new Integer(-127);
        $der = "\x2\x1" . chr(0b10000001);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative128()
    {
        $int = new Integer(-128);
        $der = "\x2\x1" . chr(0b10000000);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative129()
    {
        $int = new Integer(-129);
        $der = "\x2\x2" . chr(0b11111111) . chr(0b01111111);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative255()
    {
        $int = new Integer(-255);
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000001);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative256()
    {
        $int = new Integer(-256);
        $der = "\x2\x2" . chr(0b11111111) . chr(0b00000000);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative257()
    {
        $int = new Integer(-257);
        $der = "\x2\x2" . chr(0b11111110) . chr(0b11111111);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative32767()
    {
        $int = new Integer(-32767);
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000001);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative32768()
    {
        $int = new Integer(-32768);
        $der = "\x2\x2" . chr(0b10000000) . chr(0b00000000);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative32769()
    {
        $int = new Integer(-32769);
        $der = "\x2\x3" . chr(0b11111111) . chr(0b01111111) . chr(0b11111111);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative65535()
    {
        $int = new Integer(-65535);
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000001);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative65536()
    {
        $int = new Integer(-65536);
        $der = "\x2\x3" . chr(0b11111111) . chr(0b00000000) . chr(0b00000000);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function negative65537()
    {
        $int = new Integer(-65537);
        $der = "\x2\x3" . chr(0b11111110) . chr(0b11111111) . chr(0b11111111);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function hugePositive()
    {
        $num = gmp_init('7f' . str_repeat('ff', 0xfffe), 16);
        $int = new Integer(gmp_strval($num));
        $der = "\x2\x82\xff\xff\x7f" . str_repeat("\xff", 0xfffe);
        $this->assertEquals($der, $int->toDER());
    }

    /**
     * @test
     */
    public function hugeNegative()
    {
        $num = 0 - gmp_init('80' . str_repeat('00', 0xfffe), 16);
        $int = new Integer(gmp_strval($num));
        $der = "\x2\x82\xff\xff\x80" . str_repeat("\x00", 0xfffe);
        $this->assertEquals($der, $int->toDER());
    }
}
