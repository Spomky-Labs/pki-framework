<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\IetfAttrValue;
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
        IetfAttrValue::fromASN1(UnspecifiedType::create(new NullType()));
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
        static::assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends createOctetString
     *
     * @test
     */
    public function octetStringType(IetfAttrValue $val)
    {
        static::assertEquals(Element::TYPE_OCTET_STRING, $val->type());
    }

    /**
     * @depends createOctetString
     *
     * @test
     */
    public function isOctetString(IetfAttrValue $val)
    {
        static::assertTrue($val->isOctets());
    }

    /**
     * @depends createOctetString
     *
     * @test
     */
    public function value(IetfAttrValue $val)
    {
        static::assertEquals('test', $val->value());
    }

    /**
     * @test
     */
    public function createUTF8String()
    {
        $val = IetfAttrValue::fromString('test');
        static::assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends createUTF8String
     *
     * @test
     */
    public function uTF8StringType(IetfAttrValue $val)
    {
        static::assertEquals(Element::TYPE_UTF8_STRING, $val->type());
    }

    /**
     * @depends createUTF8String
     *
     * @test
     */
    public function isUTF8String(IetfAttrValue $val)
    {
        static::assertTrue($val->isString());
    }

    /**
     * @test
     */
    public function createOID()
    {
        $val = IetfAttrValue::fromOID('1.3.6.1.3');
        static::assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    /**
     * @depends createOID
     *
     * @test
     */
    public function oIDType(IetfAttrValue $val)
    {
        static::assertEquals(Element::TYPE_OBJECT_IDENTIFIER, $val->type());
    }

    /**
     * @depends createOID
     *
     * @test
     */
    public function isOID(IetfAttrValue $val)
    {
        static::assertTrue($val->isOID());
    }
}
