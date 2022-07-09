<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * @group element
 *
 * @internal
 */
class ElementTest extends TestCase
{
    public function testUnknownTagToName()
    {
        $this->assertEquals('TAG 100', Element::tagToName(100));
    }

    public function testIsTypeUniversalInvalidClass()
    {
        $el = new NullType();
        $cls = new ReflectionClass($el);
        $prop = $cls->getProperty('_typeTag');
        $prop->setAccessible(true);
        $prop->setValue($el, Element::TYPE_BOOLEAN);
        $this->assertFalse($el->isType(Element::TYPE_BOOLEAN));
    }

    public function testIsPseudotypeFail()
    {
        $el = new NullType();
        $this->assertFalse($el->isType(-99));
    }

    public function testAsElement()
    {
        $el = new NullType();
        $this->assertEquals($el, $el->asElement());
        return $el;
    }

    /**
     * @depends testAsElement
     */
    public function testAsUnspecified(Element $el)
    {
        $type = $el->asUnspecified();
        $this->assertInstanceOf(UnspecifiedType::class, $type);
    }

    public function testIsIndefinite()
    {
        $el = Element::fromDER(hex2bin('308005000000'))->asElement();
        $this->assertTrue($el->hasIndefiniteLength());
    }

    public function testSetDefinite()
    {
        $el = Element::fromDER(hex2bin('308005000000'))->asElement();
        $el = $el->withIndefiniteLength(false);
        $this->assertEquals(hex2bin('30020500'), $el->toDER());
    }
}
