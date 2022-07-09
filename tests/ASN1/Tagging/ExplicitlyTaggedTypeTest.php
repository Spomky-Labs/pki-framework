<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ExplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ExplicitTagging;
use Sop\ASN1\Type\TaggedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ExplicitlyTaggedTypeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new ExplicitlyTaggedType(1, new NullType());
        static::assertInstanceOf(ExplicitTagging::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function getExplicit(ExplicitTagging $el)
    {
        static::assertEquals(Element::TYPE_NULL, $el->explicit() ->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectTagged(ExplicitlyTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectTagged());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectTag(ExplicitlyTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectTagged(1));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectTagFail(ExplicitlyTaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectTagged(2);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectExplicit(TaggedType $el)
    {
        static::assertInstanceOf(ExplicitTagging::class, $el->expectExplicit());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectImplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Element doesn\'t implement implicit tagging');
        $el->expectImplicit();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectExplicitWithTag(TaggedType $el)
    {
        static::assertInstanceOf(ExplicitTagging::class, $el->expectExplicit(1));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectExplicitWithInvalidTagFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectExplicit(2);
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
    public function asExplicit(TaggedType $el)
    {
        static::assertInstanceOf(NullType::class, $el->asExplicit(1) ->asNull());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function asExplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->asExplicit(2);
    }
}
