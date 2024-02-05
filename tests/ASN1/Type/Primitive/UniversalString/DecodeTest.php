<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\UniversalString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UniversalString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = UniversalString::fromDER("\x1c\x0");
        static::assertInstanceOf(UniversalString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = "\0\0\0H\0\0\0e\0\0\0l\0\0\0l\0\0\0o";
        $el = UniversalString::fromDER("\x1c\x14{$str}");
        static::assertSame($str, $el->string());
    }

    #[Test]
    public function invalidValue()
    {
        $str = "\0\0\0H\0\0\0e\0\0\0l\0\0\0lo";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid UniversalString string');
        UniversalString::fromDER("\x1c\x11{$str}");
    }
}
