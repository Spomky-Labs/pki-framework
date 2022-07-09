<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Oid;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    public function testType()
    {
        $el = ObjectIdentifier::fromDER("\x6\0");
        $this->assertInstanceOf(ObjectIdentifier::class, $el);
    }

    public function testDecode()
    {
        $el = ObjectIdentifier::fromDER("\x06\x06\x2a\x86\x48\x86\xf7\x0d");
        $this->assertEquals('1.2.840.113549', $el->oid());
    }

    public function testFirstZero()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x0");
        $this->assertEquals('0.0', $el->oid());
    }

    public function testFirst39()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x27");
        $this->assertEquals('0.39', $el->oid());
    }

    public function testFirst40()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x28");
        $this->assertEquals('1.0', $el->oid());
    }

    public function testFirst41()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x29");
        $this->assertEquals('1.1', $el->oid());
    }

    public function testFirst79()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x4f");
        $this->assertEquals('1.39', $el->oid());
    }

    public function testFirst80()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x50");
        $this->assertEquals('2.0', $el->oid());
    }

    public function testFirstHuge()
    {
        // 0x1fffff
        $el = ObjectIdentifier::fromDER("\x6\x3\xff\xff\x7f");
        $this->assertEquals('2.2097071', $el->oid());
    }

    public function testInvalid()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data');
        ObjectIdentifier::fromDER("\x6\x3\xff\xff\xff");
    }
}
