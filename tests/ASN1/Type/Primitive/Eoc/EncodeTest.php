<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Eoc;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\EOC;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function encode()
    {
        $el = EOC::create();
        static::assertSame("\0\0", $el->toDER());
    }
}
