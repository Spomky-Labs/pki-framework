<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Oid;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    /**
     * @test
     */
    public function empty()
    {
        $oid = new ObjectIdentifier('');
        static::assertEquals("\x6\0", $oid->toDER());
    }

    /**
     * @test
     */
    public function encodeLong()
    {
        $oid = new ObjectIdentifier('1.2.840.113549');
        static::assertEquals("\x06\x06\x2a\x86\x48\x86\xf7\x0d", $oid->toDER());
    }
}
