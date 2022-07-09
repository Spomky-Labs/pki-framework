<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1\Value;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\ASN1\AttributeValue\UnknownAttributeValue;
use function strval;

/**
 * @internal
 */
final class UnknownAttributeValueTest extends TestCase
{
    final public const OID = '1.3.6.1.3';

    /**
     * @test
     */
    public function create()
    {
        $val = AttributeValue::fromASN1ByOID(self::OID, new UnspecifiedType(new UTF8String('Test')));
        $this->assertInstanceOf(UnknownAttributeValue::class, $val);
        return $val;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeValue $val)
    {
        $this->assertEquals(self::OID, $val->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function aNS1(AttributeValue $val)
    {
        $this->assertInstanceOf(UTF8String::class, $val->toASN1());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(AttributeValue $val)
    {
        $this->assertEquals('Test', $val->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(AttributeValue $val)
    {
        $this->assertIsString(strval($val));
    }
}
