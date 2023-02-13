<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\UnknownAttributeValue;
use stdClass;

/**
 * @internal
 */
final class AttributeCastTest extends TestCase
{
    private static ?Attribute $_attr = null;

    public static function setUpBeforeClass(): void
    {
        self::$_attr = Attribute::create(
            AttributeType::create(AttributeType::OID_COMMON_NAME),
            UnknownAttributeValue::create(AttributeType::OID_COMMON_NAME, UTF8String::create('name'))
        );
    }

    public static function tearDownAfterClass(): void
    {
        self::$_attr = null;
    }

    #[Test]
    public function cast()
    {
        $attr = self::$_attr->castValues(CommonNameValue::class);
        static::assertInstanceOf(CommonNameValue::class, $attr->first());
    }

    #[Test]
    public function invalidClass()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(stdClass::class . ' must be derived from ' . AttributeValue::class);
        self::$_attr->castValues(stdClass::class);
    }

    #[Test]
    public function oIDMismatch()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Attribute OID mismatch');
        self::$_attr->castValues(DescriptionValue::class);
    }
}
