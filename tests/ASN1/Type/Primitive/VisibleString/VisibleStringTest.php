<?php

declare(strict_types=1);

namespace Sop\Test\ASN1\Type\Primitive\VisibleString;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\VisibleString;
use Sop\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * @internal
 */
final class VisibleStringTest extends TestCase
{
    public function testCreate()
    {
        $el = new VisibleString('');
        $this->assertInstanceOf(VisibleString::class, $el);
        return $el;
    }

    /**
     * @depends testCreate
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_VISIBLE_STRING, $el->tag());
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
     *
     * @param string $data
     */
    public function testDecode($data): VisibleString
    {
        $el = VisibleString::fromDER($data);
        $this->assertInstanceOf(VisibleString::class, $el);
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
        $this->assertInstanceOf(VisibleString::class, $wrap->asVisibleString());
    }

    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('VisibleString expected, got primitive NULL');
        $wrap->asVisibleString();
    }
}
