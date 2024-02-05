<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\PrintableString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = PrintableString::fromDER("\x13\x0");
        static::assertInstanceOf(PrintableString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World.';
        $el = PrintableString::fromDER("\x13\x0c{$str}");
        static::assertSame($str, $el->string());
    }

    #[Test]
    public function invalidValue()
    {
        $str = 'Hello World!';
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid PrintableString string');
        PrintableString::fromDER("\x13\x0c{$str}");
    }
}
