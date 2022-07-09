<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\BmpString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\BMPString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = BMPString::fromDER("\x1e\x0");
        $this->assertInstanceOf(BMPString::class, $el);
    }

    public function testValue()
    {
        $str = "\0H\0e\0l\0l\0o\0 \0W\0o\0r\0l\0d\0!";
        $el = BMPString::fromDER("\x1e\x18{$str}");
        $this->assertEquals($str, $el->string());
    }

    public function testInvalidValue()
    {
        // last character is not 2 octets
        $str = "\0H\0e\0l\0l\0o\0 \0W\0o\0r\0l\0d!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid BMPString string');
        BMPString::fromDER("\x1e\x17{$str}");
    }
}
