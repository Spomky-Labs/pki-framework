<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\NumericString;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NumericString;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = NumericString::fromDER("\x12\x0");
        static::assertInstanceOf(NumericString::class, $el);
    }

    #[Test]
    public function value()
    {
        $str = '123 456 789 0';
        $el = NumericString::fromDER("\x12\x0d{$str}");
        static::assertSame($str, $el->string());
    }

    #[Test]
    public function invalidValue()
    {
        $str = '123-456-789-0';
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid NumericString string');
        NumericString::fromDER("\x12\x0d{$str}");
    }
}
