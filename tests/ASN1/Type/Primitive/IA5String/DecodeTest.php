<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\IA5String;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\IA5String;

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
        $el = IA5String::fromDER("\x16\x0");
        $this->assertInstanceOf(IA5String::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World!';
        $el = IA5String::fromDER("\x16\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }

    /**
     * @test
     */
    public function invalidValue()
    {
        $str = "H\xebll\xf8 W\xf6rld!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid IA5String string');
        IA5String::fromDER("\x16\x0c{$str}");
    }
}
