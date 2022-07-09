<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1\Value;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeTypeAndValue;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;

/**
 * @internal
 */
final class AttributeValueTest extends TestCase
{
    /**
     * @test
     */
    public function fromASN1BadCall()
    {
        $this->expectException(BadMethodCallException::class);
        $this->expectExceptionMessage('must be implemented in a concrete class');
        AttributeValue::fromASN1(new UnspecifiedType(new NullType()));
    }

    /**
     * @test
     */
    public function toAttribute()
    {
        $val = new CommonNameValue('name');
        static::assertInstanceOf(Attribute::class, $val->toAttribute());
    }

    /**
     * @test
     */
    public function toAttributeTypeAndValue()
    {
        $val = new CommonNameValue('name');
        static::assertInstanceOf(AttributeTypeAndValue::class, $val->toAttributeTypeAndValue());
    }
}
