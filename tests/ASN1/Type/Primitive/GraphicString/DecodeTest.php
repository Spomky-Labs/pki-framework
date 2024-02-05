<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\GraphicString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GraphicString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = GraphicString::fromDER("\x19\x0");
        static::assertInstanceOf(GraphicString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World!';
        $el = GraphicString::fromDER("\x19\x0c{$str}");
        static::assertSame($str, $el->string());
    }
}
