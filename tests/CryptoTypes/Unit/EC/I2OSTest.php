<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\EC;

use Iterator;
use PHPUnit\Framework\TestCase;
use RangeException;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;

/**
 * @internal
 */
final class I2OSTest extends TestCase
{
    /**
     * @test
     */
    public function oSType()
    {
        $os = ECConversion::integerToOctetString(new Integer(42));
        $this->assertInstanceOf(OctetString::class, $os);
    }

    /**
     * @test
     */
    public function integerType()
    {
        $num = ECConversion::octetStringToInteger(new OctetString("\x42"));
        $this->assertInstanceOf(Integer::class, $num);
    }

    /**
     * @test
     */
    public function length()
    {
        $os = ECConversion::integerToOctetString(new Integer(256), 2);
        $this->assertEquals(2, strlen($os->string()));
    }

    /**
     * @test
     */
    public function pad()
    {
        $os = ECConversion::integerToOctetString(new Integer(256), 3);
        $this->assertEquals(3, strlen($os->string()));
    }

    /**
     * @test
     */
    public function tooLarge()
    {
        $this->expectException(RangeException::class);
        ECConversion::integerToOctetString(new Integer(256), 1);
    }

    /**
     * @dataProvider provideConvert
     *
     * @param mixed $mlen
     *
     * @test
     */
    public function convert(Integer $num, $mlen, OctetString $os)
    {
        $tmp = ECConversion::integerToOctetString($num, $mlen);
        $this->assertEquals($os, $tmp);
        $result = ECConversion::octetStringToInteger($tmp);
        $this->assertEquals($num->number(), $result->number());
    }

    public function provideConvert(): Iterator
    {
        yield [new Integer(0), 1, new OctetString("\0")];
        yield [new Integer(0), 2, new OctetString("\0\0")];
        yield [new Integer(1), 1, new OctetString("\1")];
        yield [new Integer(1), 2, new OctetString("\0\1")];
        yield [new Integer(1), 8, new OctetString("\0\0\0\0\0\0\0\1")];
        yield [new Integer('4294967295'), 4, new OctetString("\xff\xff\xff\xff")];
    }

    /**
     * @test
     */
    public function numberToOctets()
    {
        $octets = ECConversion::numberToOctets(0x42);
        $this->assertEquals("\x42", $octets);
    }

    /**
     * @test
     */
    public function octetsToNumber()
    {
        $number = ECConversion::octetsToNumber("\x42");
        $this->assertEquals(0x42, $number);
    }
}
