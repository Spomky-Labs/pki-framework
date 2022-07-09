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
    public function testType()
    {
        $el = OctetString::fromDER("\x4\0");
        $this->assertInstanceOf(OctetString::class, $el);
    }

    public function testHelloWorld()
    {
        $el = OctetString::fromDER("\x4\x0cHello World!");
        $this->assertEquals('Hello World!', $el->string());
    }

    public function testNullString()
    {
        $el = OctetString::fromDER("\x4\x3\x0\x0\x0");
        $this->assertEquals("\0\0\0", $el->string());
    }
}
