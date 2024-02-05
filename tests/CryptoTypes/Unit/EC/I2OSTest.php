<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\EC;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RangeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\EC\ECConversion;
use function mb_strlen;

/**
 * @internal
 */
final class I2OSTest extends TestCase
{
    #[Test]
    public function oSType()
    {
        $os = ECConversion::integerToOctetString(Integer::create(42));
        static::assertInstanceOf(OctetString::class, $os);
    }

    #[Test]
    public function integerType()
    {
        $num = ECConversion::octetStringToInteger(OctetString::create("\x42"));
        static::assertInstanceOf(Integer::class, $num);
    }

    #[Test]
    public function length()
    {
        $os = ECConversion::integerToOctetString(Integer::create(256), 2);
        static::assertSame(2, mb_strlen($os->string(), '8bit'));
    }

    #[Test]
    public function pad()
    {
        $os = ECConversion::integerToOctetString(Integer::create(256), 3);
        static::assertSame(3, mb_strlen($os->string(), '8bit'));
    }

    #[Test]
    public function tooLarge()
    {
        $this->expectException(RangeException::class);
        ECConversion::integerToOctetString(Integer::create(256), 1);
    }

    #[Test]
    #[DataProvider('provideConvert')]
    public function convert(Integer $num, $mlen, OctetString $os)
    {
        $tmp = ECConversion::integerToOctetString($num, $mlen);
        static::assertEquals($os, $tmp);
        $result = ECConversion::octetStringToInteger($tmp);
        static::assertSame($num->number(), $result->number());
    }

    public static function provideConvert(): Iterator
    {
        yield [Integer::create(0), 1, OctetString::create("\0")];
        yield [Integer::create(0), 2, OctetString::create("\0\0")];
        yield [Integer::create(1), 1, OctetString::create("\1")];
        yield [Integer::create(1), 2, OctetString::create("\0\1")];
        yield [Integer::create(1), 8, OctetString::create("\0\0\0\0\0\0\0\1")];
        yield [Integer::create('4294967295'), 4, OctetString::create("\xff\xff\xff\xff")];
    }

    #[Test]
    public function numberToOctets()
    {
        $octets = ECConversion::numberToOctets(0x42);
        static::assertSame("\x42", $octets);
    }

    #[Test]
    public function octetsToNumber()
    {
        $number = ECConversion::octetsToNumber("\x42");
        static::assertSame((string) 0x42, $number);
    }
}
