<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type;

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
    /**
     * @test
     */
    public function asElement()
    {
        $wrap = UnspecifiedType::create(new NullType());
        static::assertInstanceOf(ElementBase::class, $wrap->asElement());
        return $wrap;
    }

    /**
     * @test
     */
    public function asUnspecified()
    {
        $wrap = UnspecifiedType::create(new NullType());
        static::assertInstanceOf(UnspecifiedType::class, $wrap->asUnspecified());
    }

    /**
     * @test
     */
    public function fromElementBase()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::fromElementBase($el);
        static::assertInstanceOf(UnspecifiedType::class, $wrap);
    }

    /**
     * @test
     */
    public function fromDER()
    {
        $el = UnspecifiedType::fromDER("\x5\0")->asNull();
        static::assertInstanceOf(NullType::class, $el);
    }

    /**
     * @depends asElement
     *
     * @test
     */
    public function fromElementBaseAsWrap(UnspecifiedType $type)
    {
        $wrap = UnspecifiedType::fromElementBase($type);
        static::assertInstanceOf(UnspecifiedType::class, $wrap);
    }

    /**
     * @test
     */
    public function asTaggedFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Tagged element expected, got primitive NULL');
        $wrap->asTagged();
    }

    /**
     * @test
     */
    public function asStringFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Any String expected, got primitive NULL');
        $wrap->asString();
    }

    /**
     * @test
     */
    public function asTimeFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Any Time expected, got primitive NULL');
        $wrap->asTime();
    }

    /**
     * @test
     */
    public function privateTypeFail()
    {
        $el = new DERData("\xdf\x7f\x0");
        $wrap = UnspecifiedType::create($el);
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('NULL expected, got primitive PRIVATE TAG 127');
        $wrap->asNull();
    }

    /**
     * @test
     */
    public function toDER()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertEquals($el->toDER(), $wrap->toDER());
    }

    /**
     * @test
     */
    public function typeClass()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertEquals($el->typeClass(), $wrap->typeClass());
    }

    /**
     * @test
     */
    public function isConstructed()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertEquals($el->isConstructed(), $wrap->isConstructed());
    }

    /**
     * @test
     */
    public function tag()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertEquals($el->tag(), $wrap->tag());
    }

    /**
     * @test
     */
    public function isTypeMethod()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertTrue($wrap->isType(Element::TYPE_NULL));
    }

    /**
     * @test
     */
    public function expectType()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(ElementBase::class, $wrap->expectType(Element::TYPE_NULL));
    }

    /**
     * @test
     */
    public function isTagged()
    {
        $el = new NullType();
        $wrap = UnspecifiedType::create($el);
        static::assertEquals($el->isTagged(), $wrap->isTagged());
    }

    /**
     * @test
     */
    public function expectTagged()
    {
        $el = new ImplicitlyTaggedType(0, new NullType());
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(ElementBase::class, $wrap->expectTagged(0));
    }
}
