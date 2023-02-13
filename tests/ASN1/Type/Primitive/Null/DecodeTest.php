<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Null;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = NullType::fromDER("\x5\0");
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    public function invalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 0, got 1');
        NullType::fromDER("\x5\x1\x0");
    }

    #[Test]
    public function notPrimitive()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Null value must be primitive');
        NullType::fromDER("\x25\x0");
    }
}
