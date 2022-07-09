<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use OutOfBoundsException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;

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
        static::assertInstanceOf(AttributeType::class, $type);
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
        static::assertIsString($der);
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
        static::assertInstanceOf(AttributeType::class, $type);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeType $type)
    {
        static::assertEquals(AttributeType::OID_NAME, $type->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(AttributeType $type)
    {
        static::assertEquals('name', $type->typeName());
    }

    /**
     * @test
     */
    public function unknownName()
    {
        static $oid = '1.3.6.1.3';
        $type = new AttributeType($oid);
        static::assertEquals($oid, $type->typeName());
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
