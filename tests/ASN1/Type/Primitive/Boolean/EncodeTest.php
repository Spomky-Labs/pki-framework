<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Boolean;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;

/**
 * @internal
 */
final class EncodeTest extends TestCase
{
    #[Test]
    public function true()
    {
        $el = Boolean::create(true);
        static::assertSame("\x1\x1\xff", $el->toDER());
    }

    #[Test]
    public function false()
    {
        $el = Boolean::create(false);
        static::assertSame("\x1\x1\x00", $el->toDER());
    }
}
