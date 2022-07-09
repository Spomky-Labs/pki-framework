<?php

declare(strict_types=1);

namespace unit\ec;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\Asymmetric\EC\ECConversion;

/**
 * @group conversion
 *
 * @internal
 */
class BitStringToOctetStringConversionTest extends TestCase
{
    public function testOSType()
    {
        $os = ECConversion::bitStringToOctetString(new BitString('test'));
        $this->assertInstanceOf(OctetString::class, $os);
    }

    public function testBSType()
    {
        $bs = ECConversion::octetStringToBitString(new OctetString('test'));
        $this->assertInstanceOf(BitString::class, $bs);
    }

    public function testUnusedBits()
    {
        $this->expectException(\RuntimeException::class);
        ECConversion::bitStringToOctetString(new BitString("\0", 4));
    }

    /**
     * @dataProvider provideConvert
     */
    public function testConvert(OctetString $os, BitString $bs)
    {
        $tmp = ECConversion::octetStringToBitString($os);
        $this->assertEquals($bs, $tmp);
        $result = ECConversion::bitStringToOctetString($tmp);
        $this->assertEquals($os, $result);
    }

    /**
     * @return array
     */
    public function provideConvert()
    {
        return [
            [new OctetString(''), new BitString('')],
            [new OctetString("\0"), new BitString("\0")],
            [new OctetString(str_repeat("\1\2\3\4", 256)),
                new BitString(str_repeat("\1\2\3\4", 256)),],
        ];
    }
}
