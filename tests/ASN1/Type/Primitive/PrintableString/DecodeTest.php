<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\PrintableString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\PrintableString;

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
        $el = PrintableString::fromDER("\x13\x0");
        $this->assertInstanceOf(PrintableString::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $str = 'Hello World.';
        $el = PrintableString::fromDER("\x13\x0c{$str}");
        $this->assertEquals($str, $el->string());
    }

    /**
     * @test
     */
    public function invalidValue()
    {
        $str = 'Hello World!';
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Not a valid PrintableString string');
        PrintableString::fromDER("\x13\x0c{$str}");
    }
}
