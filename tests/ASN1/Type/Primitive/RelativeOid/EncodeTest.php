<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\RelativeOid;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\RelativeOID;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    public function testZero()
    {
        $oid = new RelativeOID('0');
        $this->assertEquals("\x0d\1\0", $oid->toDER());
    }

    public function testEncodeLong()
    {
        $oid = new RelativeOID('1.2.840.113549');
        $this->assertEquals("\x0d\x07\x01\02\x86\x48\x86\xf7\x0d", $oid->toDER());
    }
}
