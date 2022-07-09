<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Constructed\Sequence;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;

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
        $el = Sequence::fromDER("\x30\x0");
        static::assertInstanceOf(Sequence::class, $el);
    }

    /**
     * @test
     */
    public function single()
    {
        $el = Sequence::fromDER("\x30\x2\x5\x0");
        static::assertCount(1, $el);
    }

    /**
     * @test
     */
    public function three()
    {
        $el = Sequence::fromDER("\x30\x6" . str_repeat("\x5\x0", 3));
        static::assertCount(3, $el);
    }

    /**
     * @test
     */
    public function nested()
    {
        $el = Sequence::fromDER("\x30\x2\x30\x0");
        static::assertCount(1, $el);
        static::assertEquals(Element::TYPE_SEQUENCE, $el->at(0) ->tag());
    }
}
