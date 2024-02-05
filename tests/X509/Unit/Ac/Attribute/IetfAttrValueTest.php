<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function fromUnsupportedTypeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        IetfAttrValue::fromASN1(UnspecifiedType::create(NullType::create()));
    }

    #[Test]
    public function toUnsupportedTypeFail()
    {
        $val = IetfAttrValue::create('', Element::TYPE_NULL);
        $this->expectException(LogicException::class);
        $val->toASN1();
    }

    #[Test]
    public function createOctetString()
    {
        $val = IetfAttrValue::fromOctets('test');
        static::assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    #[Test]
    #[Depends('createOctetString')]
    public function octetStringType(IetfAttrValue $val)
    {
        static::assertSame(Element::TYPE_OCTET_STRING, $val->type());
    }

    #[Test]
    #[Depends('createOctetString')]
    public function isOctetString(IetfAttrValue $val)
    {
        static::assertTrue($val->isOctets());
    }

    #[Test]
    #[Depends('createOctetString')]
    public function value(IetfAttrValue $val)
    {
        static::assertSame('test', $val->value());
    }

    #[Test]
    public function createUTF8String()
    {
        $val = IetfAttrValue::fromString('test');
        static::assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    #[Test]
    #[Depends('createUTF8String')]
    public function uTF8StringType(IetfAttrValue $val)
    {
        static::assertSame(Element::TYPE_UTF8_STRING, $val->type());
    }

    #[Test]
    #[Depends('createUTF8String')]
    public function isUTF8String(IetfAttrValue $val)
    {
        static::assertTrue($val->isString());
    }

    #[Test]
    public function createOID()
    {
        $val = IetfAttrValue::fromOID('1.3.6.1.3');
        static::assertInstanceOf(IetfAttrValue::class, $val);
        return $val;
    }

    #[Test]
    #[Depends('createOID')]
    public function oIDType(IetfAttrValue $val)
    {
        static::assertSame(Element::TYPE_OBJECT_IDENTIFIER, $val->type());
    }

    #[Test]
    #[Depends('createOID')]
    public function isOID(IetfAttrValue $val)
    {
        static::assertTrue($val->isOID());
    }
}
