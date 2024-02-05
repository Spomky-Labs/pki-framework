<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Enumerated;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Enumerated;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function encode()
    {
        $el = Enumerated::create(1);
        static::assertSame("\x0a\x1\x1", $el->toDER());
    }
}
