<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Boolean;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $el = Boolean::fromDER("\x1\x1\x00");
        static::assertInstanceOf(Boolean::class, $el);
    }

    /**
     * @test
     */
    public function true()
    {
        $el = Boolean::fromDER("\x1\x1\xff");
        static::assertTrue($el->value());
    }

    /**
     * @test
     */
    public function false()
    {
        $el = Boolean::fromDER("\x1\x1\x00");
        static::assertFalse($el->value());
    }

    /**
     * @test
     */
    public function invalidDER()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('DER encoded boolean true must have all bits set to 1');
        Boolean::fromDER("\x1\x1\x55");
    }

    /**
     * @test
     */
    public function invalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 1, got 2');
        Boolean::fromDER("\x1\x2\x00\x00");
    }
}
