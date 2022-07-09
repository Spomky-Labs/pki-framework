<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Enumerated;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\Enumerated;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $el = Enumerated::fromDER("\x0a\x1\x0");
        static::assertInstanceOf(Enumerated::class, $el);
    }

    /**
     * @test
     */
    public function value()
    {
        $el = Enumerated::fromDER("\x0a\x1\x1");
        static::assertEquals(1, $el->number());
    }
}
