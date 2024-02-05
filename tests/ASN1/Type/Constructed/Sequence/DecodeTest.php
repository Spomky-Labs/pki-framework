<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Sequence;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = Sequence::fromDER("\x30\x0");
        static::assertInstanceOf(Sequence::class, $el);
    }

    #[Test]
    public function single()
    {
        $el = Sequence::fromDER("\x30\x2\x5\x0");
        static::assertCount(1, $el);
    }

    #[Test]
    public function three()
    {
        $el = Sequence::fromDER("\x30\x6" . str_repeat("\x5\x0", 3));
        static::assertCount(3, $el);
    }

    #[Test]
    public function nested()
    {
        $el = Sequence::fromDER("\x30\x2\x30\x0");
        static::assertCount(1, $el);
        static::assertSame(Element::TYPE_SEQUENCE, $el->at(0)->tag());
    }
}
