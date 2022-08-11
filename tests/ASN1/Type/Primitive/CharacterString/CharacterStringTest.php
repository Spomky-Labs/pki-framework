<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\CharacterString;

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
    /**
     * @test
     */
    public function create()
    {
        $el = CharacterString::create('');
        static::assertInstanceOf(CharacterString::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_CHARACTER_STRING, $el->tag());
    }

    /**
     * @depends create
     *
     * @return string
     *
     * @test
     */
    public function encode(Element $el)
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @return CharacterString
     *
     * @test
     */
    public function decode($data)
    {
        $el = CharacterString::fromDER($data);
        static::assertInstanceOf(CharacterString::class, $el);
        return $el;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Element $ref, Element $el)
    {
        static::assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(CharacterString::class, $wrap->asCharacterString());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(NullType::create());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('CHARACTER STRING expected, got primitive NULL');
        $wrap->asCharacterString();
    }
}
