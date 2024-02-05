<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\RelativeOid;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\RelativeOID;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function zero()
    {
        $oid = RelativeOID::create('0');
        static::assertSame("\x0d\1\0", $oid->toDER());
    }

    #[Test]
    public function encodeLong()
    {
        $oid = RelativeOID::create('1.2.840.113549');
        static::assertSame("\x0d\x07\x01\02\x86\x48\x86\xf7\x0d", $oid->toDER());
    }
}
