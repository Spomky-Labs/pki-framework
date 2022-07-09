<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class GroupTest extends TestCase
{
    final public const AUTHORITY_DN = 'cn=Authority Name';

    final public const GROUP_NAME = 'administrators';

    /**
     * @test
     */
    public function create()
    {
        $value = new GroupAttributeValue(IetfAttrValue::fromString(self::GROUP_NAME));
        $value = $value->withPolicyAuthority(new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN)));
        $this->assertInstanceOf(GroupAttributeValue::class, $value);
        return $value;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(AttributeValue $value)
    {
        $el = $value->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
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
        $value = GroupAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(GroupAttributeValue::class, $value);
        return $value;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(AttributeValue $ref, AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeValue $value)
    {
        $this->assertEquals(GroupAttributeValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function authority(GroupAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN, $value->policyAuthority() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(GroupAttributeValue $value)
    {
        $this->assertCount(1, $value);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function groupName(GroupAttributeValue $value)
    {
        $this->assertEquals(self::GROUP_NAME, $value->first());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasGroup());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(GroupAttributeValue::class, $attribs->group());
    }
}
