<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\T61String;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\T61String;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = T61String::fromDER("\x14\x0");
        $this->assertInstanceOf(T61String::class, $el);
    }

    public function testValue()
    {
        $str = 'Hello World!';
        $el = T61String::fromDER("\x14\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }
}
