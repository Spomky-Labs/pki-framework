<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\UniversalString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\UniversalString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = UniversalString::fromDER("\x1c\x0");
        $this->assertInstanceOf(UniversalString::class, $el);
    }

    public function testValue()
    {
        $str = "\0\0\0H\0\0\0e\0\0\0l\0\0\0l\0\0\0o";
        $el = UniversalString::fromDER("\x1c\x14{$str}");
        $this->assertEquals($str, $el->string());
    }

    public function testInvalidValue()
    {
        $str = "\0\0\0H\0\0\0e\0\0\0l\0\0\0lo";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid UniversalString string');
        UniversalString::fromDER("\x1c\x11{$str}");
    }
}
