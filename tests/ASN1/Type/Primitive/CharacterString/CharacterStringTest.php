<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\CharacterString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\CharacterString;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
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
        $el = new CharacterString('');
        $this->assertInstanceOf(CharacterString::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_CHARACTER_STRING, $el->tag());
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
        $this->assertIsString($der);
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
        $this->assertInstanceOf(CharacterString::class, $el);
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
        $this->assertEquals($ref, $el);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(CharacterString::class, $wrap->asCharacterString());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('CHARACTER STRING expected, got primitive NULL');
        $wrap->asCharacterString();
    }
}
