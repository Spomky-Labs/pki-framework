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
        static::assertInstanceOf(RoleAttributeValue::class, $value);
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
        static::assertInstanceOf(Sequence::class, $el);
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
        static::assertInstanceOf(RoleAttributeValue::class, $value);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(AttributeValue $value)
    {
        static::assertEquals(AttributeType::OID_ROLE, $value->oid());
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
        static::assertInstanceOf(RoleAttributeValue::class, $value);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function roleName(RoleAttributeValue $value)
    {
        static::assertEquals(self::ROLE_URI, $value->roleName());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function roleAuthority(RoleAttributeValue $value)
    {
        static::assertEquals(self::AUTHORITY_DN, $value->roleAuthority() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasRole());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(RoleAttributeValue::class, $attribs->role());
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function allFromAttributes(Attributes $attribs)
    {
        static::assertContainsOnlyInstancesOf(RoleAttributeValue::class, $attribs->roles());
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
        static::assertCount(2, $attribs->roles());
    }

    /**
     * @test
     */
    public function createWithoutAuthority()
    {
        $value = new RoleAttributeValue(new UniformResourceIdentifier(self::ROLE_URI));
        static::assertInstanceOf(RoleAttributeValue::class, $value);
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
        static::assertInstanceOf(Sequence::class, $el);
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
        static::assertInstanceOf(RoleAttributeValue::class, $value);
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
        static::assertEquals($ref, $new);
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
        static::assertIsString($value->stringValue());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function equalityMatchingRule(AttributeValue $value)
    {
        static::assertInstanceOf(MatchingRule::class, $value->equalityMatchingRule());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function rFC2253String(AttributeValue $value)
    {
        static::assertIsString($value->rfc2253String());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function toStringMethod(AttributeValue $value)
    {
        static::assertIsString(strval($value));
    }
}
