<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ImplicitlyTaggedTypeTest extends TestCase
{
    #[Test]
    public function create(): ImplicitlyTaggedType
    {
        $el = ImplicitlyTaggedType::create(1, NullType::create());
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function getImplicit(ImplicitTagging $el)
    {
        static::assertSame(Element::TYPE_NULL, $el->implicit(Element::TYPE_NULL)->tag());
    }

    #[Test]
    #[Depends('create')]
    public function expectationFail(ImplicitTagging $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Type class PRIVATE expected, got UNIVERSAL');
        $el->implicit(Element::TYPE_NULL, Identifier::CLASS_PRIVATE);
    }

    #[Test]
    #[Depends('create')]
    public function expectImplicit(TaggedType $el)
    {
        static::assertInstanceOf(ImplicitTagging::class, $el->expectImplicit());
    }

    #[Test]
    #[Depends('create')]
    public function expectExplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Element doesn\'t implement explicit tagging');
        $el->expectExplicit();
    }

    #[Test]
    #[Depends('create')]
    public function expectImplicitWithTag(TaggedType $el)
    {
        static::assertInstanceOf(ImplicitTagging::class, $el->expectImplicit(1));
    }

    #[Test]
    #[Depends('create')]
    public function expectImplicitWithInvalidTagFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectImplicit(2);
    }

    #[Test]
    #[Depends('create')]
    public function expectTypeFails(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got CONTEXT SPECIFIC TAG 1');
        $el->expectType(Element::TYPE_NULL);
    }

    #[Test]
    #[Depends('create')]
    public function asImplicit(TaggedType $el)
    {
        static::assertInstanceOf(NullType::class, $el->asImplicit(Element::TYPE_NULL, 1)->asNull());
    }

    #[Test]
    #[Depends('create')]
    public function asImplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->asImplicit(Element::TYPE_NULL, 2);
    }
}
