<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Tagging;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\DERTaggedType;
use Sop\ASN1\Type\TaggedType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @internal
 */
final class DERTaggedTypeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        static::assertInstanceOf(DERTaggedType::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(DERTaggedType $el)
    {
        $der = $el->toDER();
        static::assertEquals("\xa0\x2\x5\x0", $der);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectExplicit(DERTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectExplicit());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function expectImplicit(DERTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectImplicit());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        static::assertInstanceOf(TaggedType::class, $wrap->asTagged());
    }
}
