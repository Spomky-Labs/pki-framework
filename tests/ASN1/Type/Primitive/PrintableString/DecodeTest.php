<?php

declare(strict_types = 1);

namespace Sop\Test\ASN1\Type\Primitive\PrintableString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\PrintableString;

/**
 * @group decode
 * @group printable-string
 *
 * @internal
 */
class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = PrintableString::fromDER("\x13\x0");
        $this->assertInstanceOf(PrintableString::class, $el);
    }

    public function testValue()
    {
        $str = 'Hello World.';
        $el = PrintableString::fromDER("\x13\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }

    public function testInvalidValue()
    {
        $str = 'Hello World!';
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid PrintableString string');
        PrintableString::fromDER("\x13\x0c{$str}");
    }
}
