<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\DERTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;

/**
 * @internal
 */
final class ExplicitlyTaggedDecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        static::assertInstanceOf(DERTaggedType::class, $el);
    }

    #[Test]
    public function tag()
    {
        $el = TaggedType::fromDER("\xa1\x2\x5\x0");
        static::assertSame(1, $el->tag());
    }

    #[Test]
    public function typeClass()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        static::assertSame(Identifier::CLASS_CONTEXT_SPECIFIC, $el->typeClass());
    }

    #[Test]
    public function constructed()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        static::assertTrue($el->isConstructed());
    }

    #[Test]
    public function innerType()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        static::assertSame(Element::TYPE_NULL, $el->explicit()->tag());
    }

    #[Test]
    public function nestedTagging()
    {
        $el = TaggedType::fromDER("\xa1\x4\xa2\x2\x5\x0");
        static::assertSame(1, $el->tag());
        static::assertSame(2, $el->explicit()->tag());
        static::assertSame(Element::TYPE_NULL, $el->explicit()->asTagged()->explicit()->tag());
    }
}
