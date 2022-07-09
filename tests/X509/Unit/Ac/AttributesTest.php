<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X509\AttributeCertificate\Attribute\AccessIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AttributesTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $attribs = Attributes::fromAttributeValues(
            new AccessIdentityAttributeValue(
                new UniformResourceIdentifier('urn:service'),
                new UniformResourceIdentifier('urn:ident')
            ),
            new RoleAttributeValue(new UniformResourceIdentifier('urn:admin')),
            new DescriptionValue('test')
        );
        $this->assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Attributes $attribs)
    {
        $seq = $attribs->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(Attributes::class, $tc);
        return $tc;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Attributes $ref, Attributes $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(Attributes $attribs)
    {
        $this->assertCount(3, $attribs);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(Attributes $attribs)
    {
        $values = [];
        foreach ($attribs as $attr) {
            $values[] = $attr;
        }
        $this->assertCount(3, $values);
        $this->assertContainsOnlyInstancesOf(Attribute::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function has(Attributes $attribs)
    {
        $this->assertTrue($attribs->has(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function firstOf(Attributes $attribs)
    {
        $this->assertInstanceOf(Attribute::class, $attribs->firstOf(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allOf(Attributes $attribs)
    {
        $this->assertCount(1, $attribs->allOf(AccessIdentityAttributeValue::OID));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAdditional(Attributes $attribs)
    {
        $attribs = $attribs->withAdditional(
            Attribute::fromAttributeValues(new GroupAttributeValue(IetfAttrValue::fromString('test')))
        );
        $this->assertInstanceOf(Attributes::class, $attribs);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withUniqueReplace(Attributes $attribs)
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(new RoleAttributeValue(new UniformResourceIdentifier('uri:new')))
        );
        $this->assertInstanceOf(Attributes::class, $attribs);
        $this->assertCount(3, $attribs);
        $this->assertEquals('uri:new', $attribs->firstOf(AttributeType::OID_ROLE) ->first() ->roleName());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withUniqueAdded(Attributes $attribs)
    {
        $attribs = $attribs->withUnique(
            Attribute::fromAttributeValues(new GroupAttributeValue(IetfAttrValue::fromString('test')))
        );
        $this->assertCount(4, $attribs);
    }
}
