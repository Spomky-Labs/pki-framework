<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\RelativeOid;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\RelativeOID;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function decode()
    {
        $el = RelativeOID::fromDER("\x0d\x07\x01\02\x86\x48\x86\xf7\x0d");
        static::assertEquals('1.2.840.113549', $el->oid());
    }
}
