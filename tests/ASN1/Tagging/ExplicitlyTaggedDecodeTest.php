<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\DERTaggedType;
use Sop\ASN1\Type\TaggedType;

/**
 * @internal
 */
final class ExplicitlyTaggedDecodeTest extends TestCase
{
    public function testType()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertInstanceOf(DERTaggedType::class, $el);
    }

    public function testTag()
    {
        $el = TaggedType::fromDER("\xa1\x2\x5\x0");
        $this->assertEquals(1, $el->tag());
    }

    public function testTypeClass()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertEquals(Identifier::CLASS_CONTEXT_SPECIFIC, $el->typeClass());
    }

    public function testConstructed()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertTrue($el->isConstructed());
    }

    public function testInnerType()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertEquals(Element::TYPE_NULL, $el->explicit() ->tag());
    }

    public function testNestedTagging()
    {
        $el = TaggedType::fromDER("\xa1\x4\xa2\x2\x5\x0");
        $this->assertEquals(1, $el->tag());
        $this->assertEquals(2, $el->explicit() ->tag());
        $this->assertEquals(Element::TYPE_NULL, $el->explicit() ->asTagged() ->explicit() ->tag());
    }
}
