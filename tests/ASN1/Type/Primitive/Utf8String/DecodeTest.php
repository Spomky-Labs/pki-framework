<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Utf8String;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\UTF8String;

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
        $el = UTF8String::fromDER("\x0c\x0");
        static::assertInstanceOf(UTF8String::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = '⠠⠓⠑⠇⠇⠕ ⠠⠺⠕⠗⠇⠙!';
        $el = UTF8String::fromDER("\x0c\x26{$str}");
        static::assertEquals($str, $el->string());
    }

    /**
     * @test
     */
    public function invalidValue()
    {
        $str = "Hello W\x94rld!";
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid UTF8String string');
        UTF8String::fromDER("\x0c\x0c{$str}");
    }
}
