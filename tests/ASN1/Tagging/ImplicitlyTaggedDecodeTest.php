<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Exception\DecodeException;
use Sop\ASN1\Type\Tagged\DERTaggedType;
use Sop\ASN1\Type\TaggedType;

/**
 * @internal
 */
final class ImplicitlyTaggedDecodeTest extends TestCase
{
    /**
     * @test
     */
    public function type()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertInstanceOf(DERTaggedType::class, $el);
    }

    /**
     * @test
     */
    public function tag()
    {
        $el = TaggedType::fromDER("\x81\x0");
        static::assertEquals(1, $el->tag());
    }

    /**
     * @test
     */
    public function typeClass()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertEquals(Identifier::CLASS_CONTEXT_SPECIFIC, $el->typeClass());
    }

    /**
     * @test
     */
    public function innerType()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertEquals(Element::TYPE_NULL, $el->implicit(Element::TYPE_NULL) ->tag());
    }

    /**
     * @test
     */
    public function innerClass()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertEquals(Identifier::CLASS_UNIVERSAL, $el->implicit(Element::TYPE_NULL) ->typeClass());
    }

    /**
     * @test
     */
    public function innerPrimitive()
    {
        $el = TaggedType::fromDER("\x80\x0");
        static::assertFalse($el->implicit(Element::TYPE_NULL) ->isConstructed());
    }

    /**
     * @test
     */
    public function innerConstructed()
    {
        $el = TaggedType::fromDER("\xa0\x0");
        static::assertTrue($el->implicit(Element::TYPE_SEQUENCE) ->isConstructed());
    }

    /**
     * Test that attempting to decode implicitly tagged sequence that doesn't have constructed bit set fails.
     *
     * @test
     */
    public function innerConstructedFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage('Structured element must have constructed bit set');
        TaggedType::fromDER("\x80\x0")->implicit(Element::TYPE_SEQUENCE);
    }

    /**
     * @test
     */
    public function nested()
    {
        $el = TaggedType::fromDER("\xa1\x2\x82\x0");
        static::assertEquals(1, $el->tag());
        $el = $el->implicit(Element::TYPE_SEQUENCE)->asSequence();
        static::assertEquals(2, $el->at(0) ->tag());
        $el = $el->at(0)
            ->asTagged()
            ->implicit(Element::TYPE_NULL);
        static::assertEquals(Element::TYPE_NULL, $el->tag());
    }
}
