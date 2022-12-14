<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1\Value;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;

/**
 * @internal
 */
final class AttributeValueTest extends TestCase
{
    /**
     * @test
     */
    public function toAttribute()
    {
        $val = CommonNameValue::create('name');
        static::assertInstanceOf(Attribute::class, $val->toAttribute());
    }

    /**
     * @test
     */
    public function toAttributeTypeAndValue()
    {
        $val = CommonNameValue::create('name');
        static::assertInstanceOf(AttributeTypeAndValue::class, $val->toAttributeTypeAndValue());
    }
}
