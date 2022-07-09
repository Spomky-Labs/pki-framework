<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;

/**
 * @internal
 */
final class IetfAttrValueTest extends TestCase
{
    public function testFromUnsupportedTypeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        IetfAttrValue::fromASN1(new UnspecifiedType(new NullType()));
    }

    public function testToUnsupportedTypeFail()
    {
        $val = new IetfAttrValue('', Element::TYPE_NULL);
        $this->expectException(\LogicException::class);
        $val->toASN1();
    }

    public function testCreateOctetString()
    {
        $val = IetfAttrValue::fromOctets('test');
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends testCreateOctetString
     */
    public function testOctetStringType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_OCTET_STRING, $val->type());
    }

    /**
     * @depends testCreateOctetString
     */
    public function testIsOctetString(IetfAttrValue $val)
    {
        $this->assertTrue($val->isOctets());
    }

    /**
     * @depends testCreateOctetString
     */
    public function testValue(IetfAttrValue $val)
    {
        $this->assertEquals('test', $val->value());
    }

    public function testCreateUTF8String()
    {
        $val = IetfAttrValue::fromString('test');
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends testCreateUTF8String
     */
    public function testUTF8StringType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_UTF8_STRING, $val->type());
    }

    /**
     * @depends testCreateUTF8String
     */
    public function testIsUTF8String(IetfAttrValue $val)
    {
        $this->assertTrue($val->isString());
    }

    public function testCreateOID()
    {
        $val = IetfAttrValue::fromOID('1.3.6.1.3');
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends testCreateOID
     */
    public function testOIDType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_OBJECT_IDENTIFIER, $val->type());
    }

    /**
     * @depends testCreateOID
     */
    public function testIsOID(IetfAttrValue $val)
    {
        $this->assertTrue($val->isOID());
    }
}
