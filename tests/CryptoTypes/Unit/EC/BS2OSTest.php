<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\EC;

use Iterator;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;

/**
 * @internal
 */
final class BS2OSTest extends TestCase
{
    /**
     * @test
     */
    public function oSType()
    {
        $os = ECConversion::bitStringToOctetString(new BitString('test'));
        $this->assertInstanceOf(OctetString::class, $os);
    }

    /**
     * @test
     */
    public function bSType()
    {
        $bs = ECConversion::octetStringToBitString(new OctetString('test'));
        $this->assertInstanceOf(BitString::class, $bs);
    }

    /**
     * @test
     */
    public function unusedBits()
    {
        $this->expectException(RuntimeException::class);
        ECConversion::bitStringToOctetString(new BitString("\0", 4));
    }

    /**
     * @dataProvider provideConvert
     *
     * @test
     */
    public function convert(OctetString $os, BitString $bs)
    {
        $tmp = ECConversion::octetStringToBitString($os);
        $this->assertEquals($bs, $tmp);
        $result = ECConversion::bitStringToOctetString($tmp);
        $this->assertEquals($os, $result);
    }

    public function provideConvert(): Iterator
    {
        yield [new OctetString(''), new BitString('')];
        yield [new OctetString("\0"), new BitString("\0")];
        yield [new OctetString(str_repeat("\1\2\3\4", 256)), new BitString(str_repeat("\1\2\3\4", 256))];
    }
}
