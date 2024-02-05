<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\GeneralString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = GeneralString::fromDER("\x1b\x0");
        static::assertInstanceOf(GeneralString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = 'Hello World!';
        $el = GeneralString::fromDER("\x1b\x0c{$str}");
        static::assertSame($str, $el->string());
    }
}
