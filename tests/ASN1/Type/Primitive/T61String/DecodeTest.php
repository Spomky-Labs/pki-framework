<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\T61String;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\T61String;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = T61String::fromDER("\x14\x0");
        static::assertInstanceOf(T61String::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World!';
        $el = T61String::fromDER("\x14\x0c{$str}");
        static::assertSame($str, $el->string());
    }
}
