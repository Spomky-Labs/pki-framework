<?php

declare(strict_types=1);

namespace unit\asn1\value;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\ASN1\AttributeValue\UnknownAttributeValue;

/**
 * @group asn1
 * @group value
 *
 * @internal
 */
class UnknownAttributeValueTest extends TestCase
{
    const OID = '1.3.6.1.3';

    public function testCreate()
    {
        $val = AttributeValue::fromASN1ByOID(self::OID,
            new UnspecifiedType(new UTF8String('Test')));
        $this->assertInstanceOf(UnknownAttributeValue::class, $val);
        return $val;
    }

    /**
     * @depends testCreate
     *
     * @param AttributeValue $val
     */
    public function testOID(AttributeValue $val)
    {
        $this->assertEquals(self::OID, $val->oid());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeValue $val
     */
    public function testANS1(AttributeValue $val)
    {
        $this->assertInstanceOf(UTF8String::class, $val->toASN1());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeValue $val
     */
    public function testString(AttributeValue $val)
    {
        $this->assertEquals('Test', $val->rfc2253String());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeValue $val
     */
    public function testToString(AttributeValue $val)
    {
        $this->assertIsString(strval($val));
    }
}
