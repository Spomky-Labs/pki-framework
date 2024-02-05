<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\OctetString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = OctetString::fromDER("\x4\0");
        static::assertInstanceOf(OctetString::class, $el);
    }

    #[Test]
    public function helloWorld()
    {
        $el = OctetString::fromDER("\x4\x0cHello World!");
        static::assertSame('Hello World!', $el->string());
    }

    #[Test]
    public function nullString()
    {
        $el = OctetString::fromDER("\x4\x3\x0\x0\x0");
        static::assertSame("\0\0\0", $el->string());
    }
}
