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
    /**
     * @test
     */
    public function type()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertInstanceOf(DERTaggedType::class, $el);
    }

    /**
     * @test
     */
    public function tag()
    {
        $el = TaggedType::fromDER("\xa1\x2\x5\x0");
        $this->assertEquals(1, $el->tag());
    }

    /**
     * @test
     */
    public function typeClass()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertEquals(Identifier::CLASS_CONTEXT_SPECIFIC, $el->typeClass());
    }

    /**
     * @test
     */
    public function constructed()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertTrue($el->isConstructed());
    }

    /**
     * @test
     */
    public function innerType()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        $this->assertEquals(Element::TYPE_NULL, $el->explicit() ->tag());
    }

    /**
     * @test
     */
    public function nestedTagging()
    {
        $el = TaggedType::fromDER("\xa1\x4\xa2\x2\x5\x0");
        $this->assertEquals(1, $el->tag());
        $this->assertEquals(2, $el->explicit() ->tag());
        $this->assertEquals(Element::TYPE_NULL, $el->explicit() ->asTagged() ->explicit() ->tag());
    }
}
