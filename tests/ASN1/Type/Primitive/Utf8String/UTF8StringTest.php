<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\Utf8String;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class UTF8StringTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $el = new UTF8String('');
        $this->assertInstanceOf(UTF8String::class, $el);
        return $el;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function tag(Element $el)
    {
        $this->assertEquals(Element::TYPE_UTF8_STRING, $el->tag());
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
     * @param string $data
     *
     * @test
     */
    public function decode($data): UTF8String
    {
        $el = UTF8String::fromDER($data);
        $this->assertInstanceOf(UTF8String::class, $el);
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
        $this->expectExceptionMessage('Not a valid UTF8String string');
        new UTF8String(hex2bin('ff'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function wrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(UTF8String::class, $wrap->asUTF8String());
    }

    /**
     * @test
     */
    public function wrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('UTF8String expected, got primitive NULL');
        $wrap->asUTF8String();
    }
}
