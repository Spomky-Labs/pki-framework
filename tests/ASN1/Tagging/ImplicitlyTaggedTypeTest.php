<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ImplicitlyTaggedTypeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new ImplicitlyTaggedType(1, new NullType());
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function getImplicit(ImplicitTagging $el)
    {
        static::assertEquals(Element::TYPE_NULL, $el->implicit(Element::TYPE_NULL) ->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectationFail(ImplicitTagging $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Type class PRIVATE expected, got UNIVERSAL');
        $el->implicit(Element::TYPE_NULL, Identifier::CLASS_PRIVATE);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectImplicit(TaggedType $el)
    {
        static::assertInstanceOf(ImplicitTagging::class, $el->expectImplicit());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectExplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Element doesn\'t implement explicit tagging');
        $el->expectExplicit();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectImplicitWithTag(TaggedType $el)
    {
        static::assertInstanceOf(ImplicitTagging::class, $el->expectImplicit(1));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectImplicitWithInvalidTagFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectImplicit(2);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectTypeFails(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got CONTEXT SPECIFIC TAG 1');
        $el->expectType(Element::TYPE_NULL);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function asImplicit(TaggedType $el)
    {
        static::assertInstanceOf(NullType::class, $el->asImplicit(Element::TYPE_NULL, 1) ->asNull());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function asImplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->asImplicit(Element::TYPE_NULL, 2);
    }
}
