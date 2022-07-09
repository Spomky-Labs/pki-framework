<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\ASN1;

use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\X501\ASN1\AttributeType;

/**
 * @internal
 */
final class AttributeTypeTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $type = AttributeType::fromName('name');
        $this->assertInstanceOf(AttributeType::class, $type);
        return $type;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AttributeType $type)
    {
        $der = $type->toASN1()
            ->toDER();
        $this->assertIsString($der);
        return $der;
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $type = AttributeType::fromASN1(ObjectIdentifier::fromDER($der));
        $this->assertInstanceOf(AttributeType::class, $type);
        return $type;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AttributeType $ref, AttributeType $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeType $type)
    {
        $this->assertEquals(AttributeType::OID_NAME, $type->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(AttributeType $type)
    {
        $this->assertEquals('name', $type->typeName());
    }

    /**
     * @test
     */
    public function unknownName()
    {
        static $oid = '1.3.6.1.3';
        $type = new AttributeType($oid);
        $this->assertEquals($oid, $type->typeName());
    }

    /**
     * @test
     */
    public function nameToOIDFail()
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('No OID for unknown');
        AttributeType::attrNameToOID('unknown');
    }
}
