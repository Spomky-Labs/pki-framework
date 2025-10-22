<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\VisibleString;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\VisibleString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class VisibleStringTest extends TestCase
{
    #[Test]
    public function create(): VisibleString
    {
        $el = VisibleString::create('');
        static::assertInstanceOf(VisibleString::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_VISIBLE_STRING, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): VisibleString
    {
        $el = VisibleString::fromDER($data);
        static::assertInstanceOf(VisibleString::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(VisibleString::class, $wrap->asVisibleString());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('VisibleString expected, got primitive NULL');
        $wrap->asVisibleString();
    }
}
