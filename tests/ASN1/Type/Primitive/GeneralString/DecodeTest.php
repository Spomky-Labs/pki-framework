<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\GeneralString;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralString;

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
        $el = GeneralString::fromDER("\x1b\x0");
        static::assertInstanceOf(GeneralString::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World!';
        $el = GeneralString::fromDER("\x1b\x0c{$str}");
        static::assertEquals($str, $el->string());
    }
}
