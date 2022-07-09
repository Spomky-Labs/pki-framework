<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\UniversalString;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\UniversalString;
use Sop\ASN1\Type\UnspecifiedType;
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
        $this->assertInstanceOf(UniversalString::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_UNIVERSAL_STRING, $el->tag());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
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
        $this->assertInstanceOf(UniversalString::class, $el);
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
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(UniversalString::class, $wrap->asUniversalString());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UniversalString expected, got primitive NULL');
        $wrap->asUniversalString();
    }
}
