<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\ASN1;

use OutOfBoundsException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;

/**
 * @internal
 */
final class AttributeTypeTest extends TestCase
{
    #[Test]
    public function create(): AttributeType
    {
        $type = AttributeType::fromName('name');
        static::assertInstanceOf(AttributeType::class, $type);
        return $type;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AttributeType $type): string
    {
        $der = $type->toASN1()
            ->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): AttributeType
    {
        $type = AttributeType::fromASN1(ObjectIdentifier::fromDER($der));
        static::assertInstanceOf(AttributeType::class, $type);
        return $type;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AttributeType $ref, AttributeType $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function oID(AttributeType $type)
    {
        static::assertSame(AttributeType::OID_NAME, $type->oid());
    }

    #[Test]
    #[Depends('create')]
    public function verifyName(?AttributeType $type = null)
    {
        static::assertSame('name', $type->typeName());
    }

    #[Test]
    public function unknownName()
    {
        static $oid = '1.3.6.1.3';
        $type = AttributeType::create($oid);
        static::assertEquals($oid, $type->typeName());
    }

    #[Test]
    public function nameToOIDFail()
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('No OID for unknown');
        AttributeType::attrNameToOID('unknown');
    }
}
