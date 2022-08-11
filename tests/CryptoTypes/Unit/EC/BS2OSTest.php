<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\EC;

use Iterator;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECConversion;

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
        $os = ECConversion::bitStringToOctetString(BitString::create('test'));
        static::assertInstanceOf(OctetString::class, $os);
    }

    /**
     * @test
     */
    public function bSType()
    {
        $bs = ECConversion::octetStringToBitString(OctetString::create('test'));
        static::assertInstanceOf(BitString::class, $bs);
    }

    /**
     * @test
     */
    public function unusedBits()
    {
        $this->expectException(RuntimeException::class);
        ECConversion::bitStringToOctetString(BitString::create("\0", 4));
    }

    /**
     * @dataProvider provideConvert
     *
     * @test
     */
    public function convert(OctetString $os, BitString $bs)
    {
        $tmp = ECConversion::octetStringToBitString($os);
        static::assertEquals($bs, $tmp);
        $result = ECConversion::bitStringToOctetString($tmp);
        static::assertEquals($os, $result);
    }

    public function provideConvert(): Iterator
    {
        yield [OctetString::create(''), BitString::create('')];
        yield [OctetString::create("\0"), BitString::create("\0")];
        yield [OctetString::create(str_repeat("\1\2\3\4", 256)), BitString::create(str_repeat("\1\2\3\4", 256))];
    }
}
