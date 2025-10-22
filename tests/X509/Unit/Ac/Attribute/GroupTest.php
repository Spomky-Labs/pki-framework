<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\GroupAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\IetfAttrValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class GroupTest extends TestCase
{
    final public const AUTHORITY_DN = 'cn=Authority Name';

    final public const GROUP_NAME = 'administrators';

    #[Test]
    public function create(): GroupAttributeValue
    {
        $value = GroupAttributeValue::create(IetfAttrValue::fromString(self::GROUP_NAME));
        $value = $value->withPolicyAuthority(GeneralNames::create(DirectoryName::fromDNString(self::AUTHORITY_DN)));
        static::assertInstanceOf(GroupAttributeValue::class, $value);
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
    public function decode($der): GroupAttributeValue
    {
        $value = GroupAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(GroupAttributeValue::class, $value);
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
        static::assertSame(GroupAttributeValue::OID, $value->oid());
    }

    #[Test]
    #[Depends('create')]
    public function authority(GroupAttributeValue $value)
    {
        static::assertSame(self::AUTHORITY_DN, $value->policyAuthority()->firstDN()->toString());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(GroupAttributeValue $value)
    {
        static::assertCount(1, $value);
    }

    #[Test]
    #[Depends('create')]
    public function groupName(GroupAttributeValue $value)
    {
        static::assertSame(self::GROUP_NAME, (string) $value->first());
    }

    #[Test]
    #[Depends('create')]
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasGroup());
        return $attribs;
    }

    #[Test]
    #[Depends('attributes')]
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(GroupAttributeValue::class, $attribs->group());
    }
}
