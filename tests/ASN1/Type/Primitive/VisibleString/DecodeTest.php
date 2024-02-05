<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\VisibleString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = VisibleString::fromDER("\x1a\x0");
        static::assertInstanceOf(VisibleString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World!';
        $el = VisibleString::fromDER("\x1a\x0c{$str}");
        static::assertSame($str, $el->string());
    }

    #[Test]
    public function invalidValue()
    {
        $str = "Hello\nWorld!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid VisibleString string');
        VisibleString::fromDER("\x1a\x0c{$str}");
    }
}
