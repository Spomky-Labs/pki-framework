<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\DERTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * @internal
 */
final class DERTaggedTypeTest extends TestCase
{
    #[Test]
    public function create(): DERTaggedType
    {
        $el = TaggedType::fromDER("\xa0\x2\x5\x0");
        static::assertInstanceOf(DERTaggedType::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function encode(DERTaggedType $el)
    {
        $der = $el->toDER();
        static::assertSame("\xa0\x2\x5\x0", $der);
    }

    #[Test]
    #[Depends('create')]
    public function expectExplicit(DERTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectExplicit());
    }

    #[Test]
    #[Depends('create')]
    public function expectImplicit(DERTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectImplicit());
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(TaggedType::class, $wrap->asTagged());
    }
}
