<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Tagged\DERTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;

/**
 * @internal
 */
final class ImplicitlyTaggedDecodeTest extends TestCase
{
    #[Test]
    public function type()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertInstanceOf(DERTaggedType::class, $el);
    }

    #[Test]
    public function tag()
    {
        $el = TaggedType::fromDER("\x81\x0");
        static::assertSame(1, $el->tag());
    }

    #[Test]
    public function typeClass()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertSame(Identifier::CLASS_CONTEXT_SPECIFIC, $el->typeClass());
    }

    #[Test]
    public function innerType()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertSame(Element::TYPE_NULL, $el->implicit(Element::TYPE_NULL)->tag());
    }

    #[Test]
    public function innerClass()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertSame(Identifier::CLASS_UNIVERSAL, $el->implicit(Element::TYPE_NULL)->typeClass());
    }

    #[Test]
    public function innerPrimitive()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertFalse($el->implicit(Element::TYPE_NULL)->isConstructed());
    }

    #[Test]
    public function innerConstructed()
    {
        $el = TaggedType::fromDER("\xa0\x0");
        static::assertTrue($el->implicit(Element::TYPE_SEQUENCE)->isConstructed());
    }

    /**
     * Test that attempting to decode implicitly tagged sequence that doesn't have constructed bit set fails.
     */
    #[Test]
    public function innerConstructedFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Structured element must have constructed bit set');
        TaggedType::fromDER("\x80\x0")->implicit(Element::TYPE_SEQUENCE);
    }

    #[Test]
    public function nested()
    {
        $el = TaggedType::fromDER("\xa1\x2\x82\x0");
        static::assertSame(1, $el->tag());
        $el = $el->implicit(Element::TYPE_SEQUENCE)->asSequence();
        static::assertSame(2, $el->at(0)->tag());
        $el = $el->at(0)
            ->asTagged()
            ->implicit(Element::TYPE_NULL);
        static::assertSame(Element::TYPE_NULL, $el->tag());
    }
}
