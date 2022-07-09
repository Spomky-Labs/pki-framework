<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\RelativeOID;

/**
 * @group decode
 * @group oid
 *
 * @internal
 */
class RelativeOIDDecodeTest extends TestCase
{
    public function testDecode()
    {
        $el = RelativeOID::fromDER("\x0d\x07\x01\02\x86\x48\x86\xf7\x0d");
        $this->assertEquals('1.2.840.113549', $el->oid());
    }
}
