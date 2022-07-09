<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Enumerated;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\Enumerated;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    public function testEncode()
    {
        $el = new Enumerated(1);
        $this->assertEquals("\x0a\x1\x1", $el->toDER());
    }
}
