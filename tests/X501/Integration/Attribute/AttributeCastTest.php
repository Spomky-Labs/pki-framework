<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\UnknownAttributeValue;

/**
 * @internal
 */
final class AttributeCastTest extends TestCase
{
    private static $_attr;

    public static function setUpBeforeClass(): void
    {
        self::$_attr = new Attribute(
            new AttributeType(AttributeType::OID_COMMON_NAME),
            new UnknownAttributeValue(AttributeType::OID_COMMON_NAME, new UTF8String('name'))
        );
    }

    public static function tearDownAfterClass(): void
    {
        self::$_attr = null;
    }

    /**
     * @test
     */
    public function cast()
    {
        $attr = self::$_attr->castValues(CommonNameValue::class);
        static::assertInstanceOf(CommonNameValue::class, $attr->first());
    }

    /**
     * @test
     */
    public function invalidClass()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(stdClass::class . ' must be derived from ' . AttributeValue::class);
        self::$_attr->castValues(stdClass::class);
    }

    /**
     * @test
     */
    public function oIDMismatch()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Attribute OID mismatch');
        self::$_attr->castValues(DescriptionValue::class);
    }
}
