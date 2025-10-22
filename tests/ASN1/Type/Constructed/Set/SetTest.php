<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Constructed\Set;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Structure;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class SetTest extends TestCase
{
    #[Test]
    public function create(): Set
    {
        $set = Set::create(NullType::create(), Boolean::create(true));
        static::assertInstanceOf(Structure::class, $set);
        return $set;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_SET, $el->tag());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $data): Set
    {
        $el = Set::fromDER($data);
        static::assertInstanceOf(Set::class, $el);
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
    public function sortSame()
    {
        $set = Set::create(NullType::create(), NullType::create());
        $sorted = $set->sortedSet();
        static::assertEquals($set, $sorted);
    }

    #[Test]
    #[Depends('create')]
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(Set::class, $wrap->asSet());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('SET expected, got primitive NULL');
        $wrap->asSet();
    }
}
