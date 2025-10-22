<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Tagging;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class ExplicitlyTaggedTypeTest extends TestCase
{
    #[Test]
    public function create(): ExplicitlyTaggedType
    {
        $el = ExplicitlyTaggedType::create(1, NullType::create());
        static::assertInstanceOf(ExplicitTagging::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function getExplicit(ExplicitTagging $el)
    {
        static::assertSame(Element::TYPE_NULL, $el->explicit()->tag());
    }

    #[Test]
    #[Depends('create')]
    public function expectTagged(ExplicitlyTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectTagged());
    }

    #[Test]
    #[Depends('create')]
    public function expectTag(ExplicitlyTaggedType $el)
    {
        static::assertInstanceOf(TaggedType::class, $el->expectTagged(1));
    }

    #[Test]
    #[Depends('create')]
    public function expectTagFail(ExplicitlyTaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectTagged(2);
    }

    #[Test]
    #[Depends('create')]
    public function expectExplicit(TaggedType $el)
    {
        static::assertInstanceOf(ExplicitTagging::class, $el->expectExplicit());
    }

    #[Test]
    #[Depends('create')]
    public function expectImplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Element doesn\'t implement implicit tagging');
        $el->expectImplicit();
    }

    #[Test]
    #[Depends('create')]
    public function expectExplicitWithTag(TaggedType $el)
    {
        static::assertInstanceOf(ExplicitTagging::class, $el->expectExplicit(1));
    }

    #[Test]
    #[Depends('create')]
    public function expectExplicitWithInvalidTagFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->expectExplicit(2);
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
    public function asExplicit(TaggedType $el)
    {
        static::assertInstanceOf(NullType::class, $el->asExplicit(1)->asNull());
    }

    #[Test]
    #[Depends('create')]
    public function asExplicitFail(TaggedType $el)
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tag 2 expected, got 1');
        $el->asExplicit(2);
    }
}
