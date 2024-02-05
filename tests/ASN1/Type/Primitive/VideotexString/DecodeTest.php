<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\VideotexString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VideotexString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = VideotexString::fromDER("\x15\x0");
        static::assertInstanceOf(VideotexString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World!';
        $el = VideotexString::fromDER("\x15\x0c{$str}");
        static::assertSame($str, $el->string());
    }
}
