<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\CharacterString;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\CharacterString;

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
        $el = CharacterString::fromDER("\x1d\x0");
        static::assertInstanceOf(CharacterString::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World!';
        $el = CharacterString::fromDER("\x1d\x0c{$str}");
        static::assertEquals($str, $el->string());
    }
}
