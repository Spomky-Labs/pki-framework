<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): Attributes
    {
        $attribs = Attributes::fromAttributeValues(
            AccessIdentityAttributeValue::create(
                UniformResourceIdentifier::create('urn:service'),
                UniformResourceIdentifier::create('urn:ident')
            ),
            RoleAttributeValue::create(UniformResourceIdentifier::create('urn:admin')),
            DescriptionValue::create('test')
        );
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    #[Test]
    #[Depends('create')]
    public function encode(Attributes $attribs): string
    {
        $seq = $attribs->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): Attributes
    {
        $tc = Attributes::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(Attributes::class, $tc);
        return $tc;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Attributes $ref, Attributes $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(Attributes $attribs): void
    {
        static::assertCount(3, $attribs);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(Attributes $attribs): void
    {
        $values = [];
        foreach ($attribs as $attr) {
            $values[] = $attr;
        }
        static::assertCount(3, $values);
        static::assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function has(Attributes $attribs): void
    {
        static::assertTrue($attribs->has(AccessIdentityAttributeValue::OID));
    }

    #[Test]
    #[Depends('create')]
    public function firstOf(Attributes $attribs): void
    {
        static::assertInstanceOf(Attribute::class, $attribs->firstOf(AccessIdentityAttributeValue::OID));
    }

    #[Test]
    #[Depends('create')]
    public function allOf(Attributes $attribs): void
    {
        static::assertCount(1, $attribs->allOf(AccessIdentityAttributeValue::OID));
    }

    #[Test]
    #[Depends('create')]
    public function withAdditional(Attributes $attribs): void
    {
        $attribs = $attribs->withAdditional(
            Attribute::fromAttributeValues(GroupAttributeValue::create(IetfAttrValue::fromString('test')))
        );
        static::assertInstanceOf(Attributes::class, $attribs);
    }

    #[Test]
    #[Depends('create')]
    public function withUniqueReplace(Attributes $attribs): void
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(RoleAttributeValue::create(UniformResourceIdentifier::create('uri:new')))
        );
        static::assertInstanceOf(Attributes::class, $attribs);
        static::assertCount(3, $attribs);
        static::assertSame('uri:new', (string) $attribs->firstOf(AttributeType::OID_ROLE)->first()->roleName());
    }

    #[Test]
    #[Depends('create')]
    public function withUniqueAdded(Attributes $attribs): void
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(GroupAttributeValue::create(IetfAttrValue::fromString('test')))
        );
        static::assertCount(4, $attribs);
    }
}
