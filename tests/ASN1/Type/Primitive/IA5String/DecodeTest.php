<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\IA5String;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = IA5String::fromDER("\x16\x0");
        static::assertInstanceOf(IA5String::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World!';
        $el = IA5String::fromDER("\x16\x0c{$str}");
        static::assertSame($str, $el->string());
    }

    #[Test]
    public function invalidValue()
    {
        $str = "H\xebll\xf8 W\xf6rld!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid IA5String string');
        IA5String::fromDER("\x16\x0c{$str}");
    }
}
