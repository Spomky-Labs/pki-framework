<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\IetfAttrValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AttributesTest extends TestCase
{
    /**
     * @test
     */
    public function create(): Attributes
    {
        $attribs = Attributes::fromAttributeValues(
            new AccessIdentityAttributeValue(
                new UniformResourceIdentifier('urn:service'),
                new UniformResourceIdentifier('urn:ident')
            ),
            new RoleAttributeValue(new UniformResourceIdentifier('urn:admin')),
            DescriptionValue::create('test')
        );
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Attributes $attribs): string
    {
        $seq = $attribs->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
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
        $tc = Attributes::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Attributes::class, $tc);
        return $tc;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Attributes $ref, Attributes $new): void
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Attributes $attribs): void
    {
        static::assertCount(3, $attribs);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(Attributes $attribs): void
    {
        $values = [];
        foreach ($attribs as $attr) {
            $values[] = $attr;
        }
        static::assertCount(3, $values);
        static::assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(Attributes $attribs): void
    {
        static::assertTrue($attribs->has(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOf(Attributes $attribs): void
    {
        static::assertInstanceOf(Attribute::class, $attribs->firstOf(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(Attributes $attribs): void
    {
        static::assertCount(1, $attribs->allOf(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAdditional(Attributes $attribs): void
    {
        $attribs = $attribs->withAdditional(
            Attribute::fromAttributeValues(GroupAttributeValue::create(IetfAttrValue::fromString('test')))
        );
        static::assertInstanceOf(Attributes::class, $attribs);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withUniqueReplace(Attributes $attribs): void
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(new RoleAttributeValue(new UniformResourceIdentifier('uri:new')))
        );
        static::assertInstanceOf(Attributes::class, $attribs);
        static::assertCount(3, $attribs);
        static::assertEquals('uri:new', $attribs->firstOf(AttributeType::OID_ROLE)->first()->roleName());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withUniqueAdded(Attributes $attribs): void
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(GroupAttributeValue::create(IetfAttrValue::fromString('test')))
        );
        static::assertCount(4, $attribs);
    }
}
