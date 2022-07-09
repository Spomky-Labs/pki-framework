<?php

declare(strict_types = 1);

namespace Sop\Test\ASN1\Type\Primitive\UniversalString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\UniversalString;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @group type
 * @group universal-string
 *
 * @internal
 */
class UniversalStringTest extends TestCase
{
    public function testCreate()
    {
        $el = new UniversalString('');
        $this->assertInstanceOf(UniversalString::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_UNIVERSAL_STRING, $el->tag());
    }

    /**
     * @depends testCreate
     */
    public function testEncode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     */
    public function testDecode(string $data): UniversalString
    {
        $el = UniversalString::fromDER($data);
        $this->assertInstanceOf(UniversalString::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(Element $ref, Element $el)
    {
        $this->assertEquals($ref, $el);
    }

    public function testInvalidString()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Not a valid UniversalString string');
        new UniversalString('xxx');
    }

    /**
     * @depends testCreate
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(UniversalString::class,
            $wrap->asUniversalString());
    }

    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(
            'UniversalString expected, got primitive NULL');
        $wrap->asUniversalString();
    }
}
