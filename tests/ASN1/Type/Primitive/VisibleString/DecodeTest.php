<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\VisibleString;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;

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
        $el = VisibleString::fromDER("\x1a\x0");
        static::assertInstanceOf(VisibleString::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World!';
        $el = VisibleString::fromDER("\x1a\x0c{$str}");
        static::assertEquals($str, $el->string());
    }

    /**
     * @test
     */
    public function invalidValue()
    {
        $str = "Hello\nWorld!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid VisibleString string');
        VisibleString::fromDER("\x1a\x0c{$str}");
    }
}
