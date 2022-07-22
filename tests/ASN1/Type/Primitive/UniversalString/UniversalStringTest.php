<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\ASN1\Type\Primitive\UniversalString;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UniversalString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class UniversalStringTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new UniversalString('');
        static::assertInstanceOf(UniversalString::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        static::assertEquals(Element::TYPE_UNIVERSAL_STRING, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(string $data): UniversalString
    {
        $el = UniversalString::fromDER($data);
        static::assertInstanceOf(UniversalString::class, $el);
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
     * @test
     */
    public function invalidString()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Not a valid UniversalString string');
        new UniversalString('xxx');
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = UnspecifiedType::create($el);
        static::assertInstanceOf(UniversalString::class, $wrap->asUniversalString());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = UnspecifiedType::create(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UniversalString expected, got primitive NULL');
        $wrap->asUniversalString();
    }
}
