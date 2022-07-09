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
 * @group decode
 * @group tagging
 * @group implicit-tag
 *
 * @internal
 */
class ImplicitlyTaggedDecodeTest extends TestCase
{
    public function testType()
    {
        $el = TaggedType::fromDER("\x80\x0");
        $this->assertInstanceOf(DERTaggedType::class, $el);
    }

    public function testTag()
    {
        $el = TaggedType::fromDER("\x81\x0");
        $this->assertEquals(1, $el->tag());
    }

    public function testTypeClass()
    {
        $el = TaggedType::fromDER("\x80\x0");
        $this->assertEquals(Identifier::CLASS_CONTEXT_SPECIFIC, $el->typeClass());
    }

    public function testInnerType()
    {
        $el = TaggedType::fromDER("\x80\x0");
        $this->assertEquals(
            Element::TYPE_NULL,
            $el->implicit(Element::TYPE_NULL)
                ->tag()
        );
    }

    public function testInnerClass()
    {
        $el = TaggedType::fromDER("\x80\x0");
        $this->assertEquals(
            Identifier::CLASS_UNIVERSAL,
            $el->implicit(Element::TYPE_NULL)
                ->typeClass()
        );
    }

    public function testInnerPrimitive()
    {
        $el = TaggedType::fromDER("\x80\x0");
        $this->assertFalse(
            $el->implicit(Element::TYPE_NULL)
                ->isConstructed()
        );
    }

    public function testInnerConstructed()
    {
        $el = TaggedType::fromDER("\xa0\x0");
        $this->assertTrue(
            $el->implicit(Element::TYPE_SEQUENCE)
                ->isConstructed()
        );
    }

    /**
     * Test that attempting to decode implicitly tagged sequence that
     * doesn't have constructed bit set fails.
     */
    public function testInnerConstructedFail()
    {
        $this->expectException(DecodeException::class);
        $this->expectExceptionMessage(
            'Structured element must have constructed bit set'
        );
        TaggedType::fromDER("\x80\x0")->implicit(Element::TYPE_SEQUENCE);
    }

    public function testNested()
    {
        $el = TaggedType::fromDER("\xa1\x2\x82\x0");
        $this->assertEquals(1, $el->tag());
        $el = $el->implicit(Element::TYPE_SEQUENCE)->asSequence();
        $this->assertEquals(2, $el->at(0)
            ->tag());
        $el = $el->at(0)->asTagged()->implicit(Element::TYPE_NULL);
        $this->assertEquals(Element::TYPE_NULL, $el->tag());
    }
}
