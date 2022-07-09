<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\MatchingRule\MatchingRule;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;
use function strval;

/**
 * @internal
 */
final class RoleTest extends TestCase
{
    final public const ROLE_URI = 'urn:administrator';

    final public const AUTHORITY_DN = 'cn=Role Authority';

    /**
     * @test
     */
    public function create()
    {
        $value = new RoleAttributeValue(
            new UniformResourceIdentifier(self::ROLE_URI),
            new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN))
        );
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
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
        $value = RoleAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
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
        $this->assertEquals(AttributeType::OID_ROLE, $value->oid());
    }

    /**
     * @test
     */
    public function fromString()
    {
        $value = RoleAttributeValue::fromString(
            self::ROLE_URI,
            new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN))
        );
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function roleName(RoleAttributeValue $value)
    {
        $this->assertEquals(self::ROLE_URI, $value->roleName());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function roleAuthority(RoleAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN, $value->roleAuthority() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasRole());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(RoleAttributeValue::class, $attribs->role());
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function allFromAttributes(Attributes $attribs)
    {
        $this->assertContainsOnlyInstancesOf(RoleAttributeValue::class, $attribs->roles());
    }

    /**
     * @test
     */
    public function allFromMultipleAttributes()
    {
        $attribs = Attributes::fromAttributeValues(
            RoleAttributeValue::fromString('urn:role:1'),
            RoleAttributeValue::fromString('urn:role:2')
        );
        $this->assertCount(2, $attribs->roles());
    }

    /**
     * @test
     */
    public function createWithoutAuthority()
    {
        $value = new RoleAttributeValue(new UniformResourceIdentifier(self::ROLE_URI));
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }

    /**
     * @depends createWithoutAuthority
     *
     * @test
     */
    public function encodeWithoutAuthority(AttributeValue $value)
    {
        $el = $value->toASN1();
        $this->assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithoutAuthority
     *
     * @param string $der
     *
     * @test
     */
    public function decodeWithoutAuthority($der)
    {
        $value = RoleAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }

    /**
     * @depends createWithoutAuthority
     * @depends decodeWithoutAuthority
     *
     * @test
     */
    public function recodedWithoutAuthority(AttributeValue $ref, AttributeValue $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithoutAuthority
     *
     * @test
     */
    public function noRoleAuthorityFail(RoleAttributeValue $value)
    {
        $this->expectException(LogicException::class);
        $value->roleAuthority();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function stringValue(AttributeValue $value)
    {
        $this->assertIsString($value->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function equalityMatchingRule(AttributeValue $value)
    {
        $this->assertInstanceOf(MatchingRule::class, $value->equalityMatchingRule());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rFC2253String(AttributeValue $value)
    {
        $this->assertIsString($value->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(AttributeValue $value)
    {
        $this->assertIsString(strval($value));
    }
}
