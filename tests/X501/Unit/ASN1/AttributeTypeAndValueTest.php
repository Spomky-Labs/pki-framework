<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\NameValue;

/**
 * @group asn1
 *
 * @internal
 */
class AttributeTypeAndValueTest extends TestCase
{
    public function testCreate()
    {
        $atv = AttributeTypeAndValue::fromAttributeValue(new NameValue('one'));
        $this->assertInstanceOf(AttributeTypeAndValue::class, $atv);
        return $atv;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(AttributeTypeAndValue $atv)
    {
        $der = $atv->toASN1()->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $atv = AttributeTypeAndValue::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AttributeTypeAndValue::class, $atv);
        return $atv;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(
        AttributeTypeAndValue $ref,
        AttributeTypeAndValue $new
    ) {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testValue(AttributeTypeAndValue $atv)
    {
        $this->assertEquals('one', $atv->value()->rfc2253String());
    }

    /**
     * @depends testCreate
     */
    public function testString(AttributeTypeAndValue $atv)
    {
        $this->assertEquals('name=one', $atv->toString());
    }

    /**
     * @depends testCreate
     */
    public function testToString(AttributeTypeAndValue $atv)
    {
        $this->assertIsString(strval($atv));
    }
}
