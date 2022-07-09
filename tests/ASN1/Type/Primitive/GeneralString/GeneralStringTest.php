<?php

declare(strict_types = 1);

namespace Sop\Test\ASN1\Type\Primitive\GeneralString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\GeneralString;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @group type
 * @group general-string
 *
 * @internal
 */
class GeneralStringTest extends TestCase
{
    public function testCreate()
    {
        $el = new GeneralString('');
        $this->assertInstanceOf(GeneralString::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_GENERAL_STRING, $el->tag());
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
    public function testDecode(string $data): GeneralString
    {
        $el = GeneralString::fromDER($data);
        $this->assertInstanceOf(GeneralString::class, $el);
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

    /**
     * @depends testCreate
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(GeneralString::class, $wrap->asGeneralString());
    }

    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(
            'GeneralString expected, got primitive NULL');
        $wrap->asGeneralString();
    }
}
