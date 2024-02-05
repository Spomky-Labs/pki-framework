<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Oid;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function empty()
    {
        $oid = ObjectIdentifier::create('');
        static::assertSame("\x6\0", $oid->toDER());
    }

    #[Test]
    public function encodeLong()
    {
        $oid = ObjectIdentifier::create('1.2.840.113549');
        static::assertSame("\x06\x06\x2a\x86\x48\x86\xf7\x0d", $oid->toDER());
    }
}
