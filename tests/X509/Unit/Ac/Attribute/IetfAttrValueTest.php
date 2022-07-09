<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use UnexpectedValueException;

/**
 * @internal
 */
final class IetfAttrValueTest extends TestCase
{
    /**
     * @test
     */
    public function fromUnsupportedTypeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        IetfAttrValue::fromASN1(new UnspecifiedType(new NullType()));
    }

    /**
     * @test
     */
    public function toUnsupportedTypeFail()
    {
        $val = new IetfAttrValue('', Element::TYPE_NULL);
        $this->expectException(LogicException::class);
        $val->toASN1();
    }

    /**
     * @test
     */
    public function createOctetString()
    {
        $val = IetfAttrValue::fromOctets('test');
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends createOctetString
     *
     * @test
     */
    public function octetStringType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_OCTET_STRING, $val->type());
    }

    /**
     * @depends createOctetString
     *
     * @test
     */
    public function isOctetString(IetfAttrValue $val)
    {
        $this->assertTrue($val->isOctets());
    }

    /**
     * @depends createOctetString
     *
     * @test
     */
    public function value(IetfAttrValue $val)
    {
        $this->assertEquals('test', $val->value());
    }

    /**
     * @test
     */
    public function createUTF8String()
    {
        $val = IetfAttrValue::fromString('test');
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends createUTF8String
     *
     * @test
     */
    public function uTF8StringType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_UTF8_STRING, $val->type());
    }

    /**
     * @depends createUTF8String
     *
     * @test
     */
    public function isUTF8String(IetfAttrValue $val)
    {
        $this->assertTrue($val->isString());
    }

    /**
     * @test
     */
    public function createOID()
    {
        $val = IetfAttrValue::fromOID('1.3.6.1.3');
        $this->assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends createOID
     *
     * @test
     */
    public function oIDType(IetfAttrValue $val)
    {
        $this->assertEquals(Element::TYPE_OBJECT_IDENTIFIER, $val->type());
    }

    /**
     * @depends createOID
     *
     * @test
     */
    public function isOID(IetfAttrValue $val)
    {
        $this->assertTrue($val->isOID());
    }
}
