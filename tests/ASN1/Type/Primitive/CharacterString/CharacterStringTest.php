<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\CharacterString;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\CharacterString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class CharacterStringTest extends TestCase
{
    #[Test]
    public function create(): CharacterString
    {
        $el = CharacterString::create('');
        static::assertInstanceOf(CharacterString::class, $el);
        return $el;
    }

    #[Test]
    #[Depends('create')]
    public function tag(Element $el)
    {
        static::assertSame(Element::TYPE_CHARACTER_STRING, $el->tag());
    }

    /**
     * @return string
     */
    #[Test]
    #[Depends('create')]
    public function encode(Element $el)
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $data
     *
     * @return CharacterString
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data)
    {
        $el = CharacterString::fromDER($data);
        static::assertInstanceOf(CharacterString::class, $el);
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
        static::assertInstanceOf(CharacterString::class, $wrap->asCharacterString());
    }

    #[Test]
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('CHARACTER STRING expected, got primitive NULL');
        $wrap->asCharacterString();
    }
}
