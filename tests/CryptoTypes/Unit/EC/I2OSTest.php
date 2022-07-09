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
    public function testOSType()
    {
        $os = ECConversion::integerToOctetString(new Integer(42));
        $this->assertInstanceOf(OctetString::class, $os);
    }

    public function testIntegerType()
    {
        $num = ECConversion::octetStringToInteger(new OctetString("\x42"));
        $this->assertInstanceOf(Integer::class, $num);
    }

    public function testLength()
    {
        $os = ECConversion::integerToOctetString(new Integer(256), 2);
        $this->assertEquals(2, strlen($os->string()));
    }

    public function testPad()
    {
        $os = ECConversion::integerToOctetString(new Integer(256), 3);
        $this->assertEquals(3, strlen($os->string()));
    }

    public function testTooLarge()
    {
        $this->expectException(RangeException::class);
        ECConversion::integerToOctetString(new Integer(256), 1);
    }

    /**
     * @dataProvider provideConvert
     *
     * @param mixed $mlen
     */
    public function testConvert(Integer $num, $mlen, OctetString $os)
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

    public function testNumberToOctets()
    {
        $octets = ECConversion::numberToOctets(0x42);
        $this->assertEquals("\x42", $octets);
    }

    public function testOctetsToNumber()
    {
        $number = ECConversion::octetsToNumber("\x42");
        $this->assertEquals(0x42, $number);
    }
}
