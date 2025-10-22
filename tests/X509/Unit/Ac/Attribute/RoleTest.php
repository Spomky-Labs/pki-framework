<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\MatchingRule\MatchingRule;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use function strval;

/**
 * @internal
 */
final class RoleTest extends TestCase
{
    final public const ROLE_URI = 'urn:administrator';

    final public const AUTHORITY_DN = 'cn=Role Authority';

    #[Test]
    public function create(): RoleAttributeValue
    {
        $value = RoleAttributeValue::create(
            UniformResourceIdentifier::create(self::ROLE_URI),
            GeneralNames::create(DirectoryName::fromDNString(self::AUTHORITY_DN))
        );
        static::assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AttributeValue $value): string
    {
        $el = $value->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): RoleAttributeValue
    {
        $value = RoleAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AttributeValue $ref, AttributeValue $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function oID(AttributeValue $value)
    {
        static::assertSame(AttributeType::OID_ROLE, $value->oid());
    }

    #[Test]
    public function fromString()
    {
        $value = RoleAttributeValue::fromString(
            self::ROLE_URI,
            GeneralNames::create(DirectoryName::fromDNString(self::AUTHORITY_DN))
        );
        static::assertInstanceOf(RoleAttributeValue::class, $value);
    }

    #[Test]
    #[Depends('create')]
    public function roleName(RoleAttributeValue $value)
    {
        static::assertSame(self::ROLE_URI, $value->roleName()->string());
    }

    #[Test]
    #[Depends('create')]
    public function roleAuthority(RoleAttributeValue $value)
    {
        static::assertSame(self::AUTHORITY_DN, $value->roleAuthority()->firstDN()->toString());
    }

    #[Test]
    #[Depends('create')]
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasRole());
        return $attribs;
    }

    #[Test]
    #[Depends('attributes')]
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(RoleAttributeValue::class, $attribs->role());
    }

    #[Test]
    #[Depends('attributes')]
    public function allFromAttributes(Attributes $attribs)
    {
        static::assertContainsOnlyInstancesOf(RoleAttributeValue::class, $attribs->roles());
    }

    #[Test]
    public function allFromMultipleAttributes()
    {
        $attribs = Attributes::fromAttributeValues(
            RoleAttributeValue::fromString('urn:role:1'),
            RoleAttributeValue::fromString('urn:role:2')
        );
        static::assertCount(2, $attribs->roles());
    }

    #[Test]
    public function createWithoutAuthority()
    {
        $value = RoleAttributeValue::create(UniformResourceIdentifier::create(self::ROLE_URI));
        static::assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }

    #[Test]
    #[Depends('createWithoutAuthority')]
    public function encodeWithoutAuthority(AttributeValue $value)
    {
        $el = $value->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encodeWithoutAuthority')]
    public function decodeWithoutAuthority($der)
    {
        $value = RoleAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(RoleAttributeValue::class, $value);
        return $value;
    }

    #[Test]
    #[Depends('createWithoutAuthority')]
    #[Depends('decodeWithoutAuthority')]
    public function recodedWithoutAuthority(AttributeValue $ref, AttributeValue $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithoutAuthority')]
    public function noRoleAuthorityFail(RoleAttributeValue $value)
    {
        $this->expectException(LogicException::class);
        $value->roleAuthority();
    }

    #[Test]
    #[Depends('create')]
    public function stringValue(AttributeValue $value)
    {
        static::assertIsString($value->stringValue());
    }

    #[Test]
    #[Depends('create')]
    public function equalityMatchingRule(AttributeValue $value)
    {
        static::assertInstanceOf(MatchingRule::class, $value->equalityMatchingRule());
    }

    #[Test]
    #[Depends('create')]
    public function rFC2253String(AttributeValue $value)
    {
        static::assertIsString($value->rfc2253String());
    }

    #[Test]
    #[Depends('create')]
    public function toStringMethod(AttributeValue $value)
    {
        static::assertIsString(strval($value));
    }
}
