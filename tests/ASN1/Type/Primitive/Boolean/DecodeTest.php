<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Boolean;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = Boolean::fromDER("\x1\x1\x00");
        static::assertInstanceOf(Boolean::class, $el);
    }

    #[Test]
    public function true()
    {
        $el = Boolean::fromDER("\x1\x1\xff");
        static::assertTrue($el->value());
    }

    #[Test]
    public function false()
    {
        $el = Boolean::fromDER("\x1\x1\x00");
        static::assertFalse($el->value());
    }

    #[Test]
    public function invalidDER()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('DER encoded boolean true must have all bits set to 1');
        Boolean::fromDER("\x1\x1\x55");
    }

    #[Test]
    public function invalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 1, got 2');
        Boolean::fromDER("\x1\x2\x00\x00");
    }
}
