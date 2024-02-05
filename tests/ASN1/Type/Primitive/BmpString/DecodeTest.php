<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\BmpString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BMPString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = BMPString::fromDER("\x1e\x0");
        static::assertInstanceOf(BMPString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = "\0H\0e\0l\0l\0o\0 \0W\0o\0r\0l\0d\0!";
        $el = BMPString::fromDER("\x1e\x18{$str}");
        static::assertSame($str, $el->string());
    }

    #[Test]
    public function invalidValue()
    {
        // last character is not 2 octets
        $str = "\0H\0e\0l\0l\0o\0 \0W\0o\0r\0l\0d!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid BMPString string');
        BMPString::fromDER("\x1e\x17{$str}");
    }
}
