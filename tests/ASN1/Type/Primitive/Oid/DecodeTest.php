<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Oid;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function emptyContentOctetsAreRejected()
    {
        // X.690 sect. 8.19.1: an object identifier has at least one sub-identifier
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Object identifier must have at least one content octet.');
        ObjectIdentifier::fromDER("\x6\0");
    }

    #[Test]
    public function decode()
    {
        $el = ObjectIdentifier::fromDER("\x06\x06\x2a\x86\x48\x86\xf7\x0d");
        static::assertSame('1.2.840.113549', $el->oid());
    }

    #[Test]
    public function firstZero()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x0");
        static::assertSame('0.0', $el->oid());
    }

    #[Test]
    public function first39()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x27");
        static::assertSame('0.39', $el->oid());
    }

    #[Test]
    public function first40()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x28");
        static::assertSame('1.0', $el->oid());
    }

    #[Test]
    public function first41()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x29");
        static::assertSame('1.1', $el->oid());
    }

    #[Test]
    public function first79()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x4f");
        static::assertSame('1.39', $el->oid());
    }

    #[Test]
    public function first80()
    {
        $el = ObjectIdentifier::fromDER("\x6\x1\x50");
        static::assertSame('2.0', $el->oid());
    }

    #[Test]
    public function firstHuge()
    {
        // 0x1fffff
        $el = ObjectIdentifier::fromDER("\x6\x3\xff\xff\x7f");
        static::assertSame('2.2097071', $el->oid());
    }

    #[Test]
    public function invalid()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Unexpected end of data');
        ObjectIdentifier::fromDER("\x6\x3\xff\xff\xff");
    }
}
