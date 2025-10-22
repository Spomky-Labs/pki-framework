<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Value;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\UnknownAttributeValue;
use function strval;

/**
 * @internal
 */
final class UnknownAttributeValueTest extends TestCase
{
    final public const OID = '1.3.6.1.3';

    #[Test]
    public function create(): UnknownAttributeValue
    {
        $val = AttributeValue::fromASN1ByOID(self::OID, UnspecifiedType::create(UTF8String::create('Test')));
        static::assertInstanceOf(UnknownAttributeValue::class, $val);
        return $val;
    }

    #[Test]
    #[Depends('create')]
    public function oID(AttributeValue $val)
    {
        static::assertSame(self::OID, $val->oid());
    }

    #[Test]
    #[Depends('create')]
    public function aNS1(AttributeValue $val)
    {
        static::assertInstanceOf(UTF8String::class, $val->toASN1());
    }

    #[Test]
    #[Depends('create')]
    public function string(AttributeValue $val)
    {
        static::assertSame('Test', $val->rfc2253String());
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(AttributeValue $val)
    {
        static::assertIsString(strval($val));
    }
}
