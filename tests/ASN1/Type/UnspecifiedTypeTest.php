<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\DERData;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class UnspecifiedTypeTest extends TestCase
{
    #[Test]
    public function asElement(): UnspecifiedType
    {
        $wrap = UnspecifiedType::create(NullType::create());
        static::assertInstanceOf(ElementBase::class, $wrap->asElement());
        return $wrap;
    }

    #[Test]
    public function asUnspecified()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        static::assertInstanceOf(UnspecifiedType::class, $wrap->asUnspecified());
    }

    #[Test]
    public function fromElementBase()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::fromElementBase($el);
        static::assertInstanceOf(UnspecifiedType::class, $wrap);
    }

    #[Test]
    public function fromDER()
    {
        $el = UnspecifiedType::fromDER("\x5\0")->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    #[Test]
    #[Depends('asElement')]
    public function fromElementBaseAsWrap(UnspecifiedType $type)
    {
        $wrap = UnspecifiedType::fromElementBase($type);
        static::assertInstanceOf(UnspecifiedType::class, $wrap);
    }

    #[Test]
    public function asTaggedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tagged element expected, got primitive NULL');
        $wrap->asTagged();
    }

    #[Test]
    public function asStringFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Any String expected, got primitive NULL');
        $wrap->asString();
    }

    #[Test]
    public function asTimeFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Any Time expected, got primitive NULL');
        $wrap->asTime();
    }

    #[Test]
    public function privateTypeFail()
    {
        $el = DERData::create("\xdf\x7f\x0");
        $wrap = UnspecifiedType::create($el);
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got primitive PRIVATE TAG 127');
        $wrap->asNull();
    }

    #[Test]
    public function toDER()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertSame($el->toDER(), $wrap->toDER());
    }

    #[Test]
    public function typeClass()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertSame($el->typeClass(), $wrap->typeClass());
    }

    #[Test]
    public function isConstructed()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertSame($el->isConstructed(), $wrap->isConstructed());
    }

    #[Test]
    public function tag()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertSame($el->tag(), $wrap->tag());
    }

    #[Test]
    public function isTypeMethod()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertTrue($wrap->isType(Element::TYPE_NULL));
    }

    #[Test]
    public function expectType()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(ElementBase::class, $wrap->expectType(Element::TYPE_NULL));
    }

    #[Test]
    public function isTagged()
    {
        $el = NullType::create();
        $wrap = UnspecifiedType::create($el);
        static::assertSame($el->isTagged(), $wrap->isTagged());
    }

    #[Test]
    public function expectTagged()
    {
        $el = ImplicitlyTaggedType::create(0, NullType::create());
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(ElementBase::class, $wrap->expectTagged(0));
    }
}
