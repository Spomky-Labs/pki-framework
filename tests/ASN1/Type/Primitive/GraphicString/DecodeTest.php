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
    public function testType()
    {
        $el = GraphicString::fromDER("\x19\x0");
        $this->assertInstanceOf(GraphicString::class, $el);
    }

    public function testValue()
    {
        $str = 'Hello World!';
        $el = GraphicString::fromDER("\x19\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }
}
