<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\GraphicString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\GraphicString;

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
        $el = GraphicString::fromDER("\x19\x0");
        static::assertInstanceOf(GraphicString::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World!';
        $el = GraphicString::fromDER("\x19\x0c{$str}");
        static::assertEquals($str, $el->string());
    }
}
