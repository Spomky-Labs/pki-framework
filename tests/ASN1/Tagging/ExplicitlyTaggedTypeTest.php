<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;

/**
 * @internal
 */
final class ExplicitlyTaggedTypeTest extends TestCase
{
    public function testCreate()
    {
        $el = new ExplicitlyTaggedType(1, new NullType());
        $this->assertInstanceOf(ExplicitTagging::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testGetExplicit(ExplicitTagging $el)
    {
        $this->assertEquals(Element::TYPE_NULL, $el->explicit() ->tag());
    }

    /**
     * @depends testCreate
     */
    public function testExpectTagged(ExplicitlyTaggedType $el)
    {
        $this->assertInstanceOf(TaggedType::class, $el->expectTagged());
    }

    /**
     * @depends testCreate
     */
    public function testExpectTag(ExplicitlyTaggedType $el)
    {
        $this->assertInstanceOf(TaggedType::class, $el->expectTagged(1));
    }

    /**
     * @depends testCreate
     */
    public function testExpectTagFail(ExplicitlyTaggedType $el)
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectTagged(2);
    }

    /**
     * @depends testCreate
     */
    public function testExpectExplicit(TaggedType $el)
    {
        $this->assertInstanceOf(ExplicitTagging::class, $el->expectExplicit());
    }

    /**
     * @depends testCreate
     */
    public function testExpectImplicitFail(TaggedType $el)
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Element doesn\'t implement implicit tagging');
        $el->expectImplicit();
    }

    /**
     * @depends testCreate
     */
    public function testExpectExplicitWithTag(TaggedType $el)
    {
        $this->assertInstanceOf(ExplicitTagging::class, $el->expectExplicit(1));
    }

    /**
     * @depends testCreate
     */
    public function testExpectExplicitWithInvalidTagFail(TaggedType $el)
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectExplicit(2);
    }

    /**
     * @depends testCreate
     */
    public function testExpectTypeFails(TaggedType $el)
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got CONTEXT SPECIFIC TAG 1');
        $el->expectType(Element::TYPE_NULL);
    }

    /**
     * @depends testCreate
     */
    public function testAsExplicit(TaggedType $el)
    {
        $this->assertInstanceOf(NullType::class, $el->asExplicit(1) ->asNull());
    }

    /**
     * @depends testCreate
     */
    public function testAsExplicitFail(TaggedType $el)
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->asExplicit(2);
    }
}
