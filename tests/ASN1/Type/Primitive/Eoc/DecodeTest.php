<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Eoc;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\EOC;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = EOC::fromDER("\0\0");
        static::assertInstanceOf(EOC::class, $el);
    }

    #[Test]
    public function invalidLength()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Expected length 0, got 1');
        EOC::fromDER("\x0\x1\x0");
    }

    #[Test]
    public function notPrimitive()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('EOC value must be primitive');
        EOC::fromDER("\x20\x0");
    }
}
