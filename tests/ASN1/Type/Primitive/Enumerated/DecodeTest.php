<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\Enumerated;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Enumerated;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = Enumerated::fromDER("\x0a\x1\x0");
        static::assertInstanceOf(Enumerated::class, $el);
    }

    #[Test]
    public function value()
    {
        $el = Enumerated::fromDER("\x0a\x1\x1");
        static::assertSame('1', $el->number());
    }
}
