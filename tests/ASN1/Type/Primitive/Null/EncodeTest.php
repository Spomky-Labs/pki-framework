<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Null;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    public function testEncode()
    {
        $el = new NullType();
        $this->assertEquals("\x5\x0", $el->toDER());
    }
}
