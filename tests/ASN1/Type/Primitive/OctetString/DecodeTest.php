<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\OctetString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\OctetString;

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
        $el = OctetString::fromDER("\x4\0");
        static::assertInstanceOf(OctetString::class, $el);
    }

    /**
     * @test
     */
    public function helloWorld()
    {
        $el = OctetString::fromDER("\x4\x0cHello World!");
        static::assertEquals('Hello World!', $el->string());
    }

    /**
     * @test
     */
    public function nullString()
    {
        $el = OctetString::fromDER("\x4\x3\x0\x0\x0");
        static::assertEquals("\0\0\0", $el->string());
    }
}
