<?php

declare(strict_types=1);

namespace unit\asn1;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\X501\ASN1\AttributeType;

/**
 * @group asn1
 *
 * @internal
 */
class AttributeTypeTest extends TestCase
{
    public function testCreate()
    {
        $type = AttributeType::fromName('name');
        $this->assertInstanceOf(AttributeType::class, $type);
        return $type;
    }

    /**
     * @depends testCreate
     *
     * @param AttributeType $type
     */
    public function testEncode(AttributeType $type)
    {
        $der = $type->toASN1()->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $type = AttributeType::fromASN1(ObjectIdentifier::fromDER($der));
        $this->assertInstanceOf(AttributeType::class, $type);
        return $type;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param AttributeType $ref
     * @param AttributeType $new
     */
    public function testRecoded(AttributeType $ref, AttributeType $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param AttributeType $type
     */
    public function testOID(AttributeType $type)
    {
        $this->assertEquals(AttributeType::OID_NAME, $type->oid());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeType $type
     */
    public function testName(AttributeType $type)
    {
        $this->assertEquals('name', $type->typeName());
    }

    public function testUnknownName()
    {
        static $oid = '1.3.6.1.3';
        $type = new AttributeType($oid);
        $this->assertEquals($oid, $type->typeName());
    }

    public function testNameToOIDFail()
    {
        $this->expectException(\OutOfBoundsException::class);
        $this->expectExceptionMessage('No OID for unknown');
        AttributeType::attrNameToOID('unknown');
    }
}
