<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\IetfAttrValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class ChargingIdentityTest extends TestCase
{
    final public const AUTHORITY_DN = 'cn=Authority Name';

    final public const OCTETS_VAL = 'octet string';

    final public const OID_VAL = '1.3.6.1.3.1';

    final public const UTF8_VAL = 'UTF-8 string';

    #[Test]
    public function create(): ChargingIdentityAttributeValue
    {
        $value = ChargingIdentityAttributeValue::create(
            IetfAttrValue::fromOctets(self::OCTETS_VAL),
            IetfAttrValue::fromOID(self::OID_VAL),
            IetfAttrValue::fromString(self::UTF8_VAL)
        );
        $value = $value->withPolicyAuthority(GeneralNames::create(DirectoryName::fromDNString(self::AUTHORITY_DN)));
        static::assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
    public function decode($der): ChargingIdentityAttributeValue
    {
        $value = ChargingIdentityAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
        static::assertSame(ChargingIdentityAttributeValue::OID, $value->oid());
    }

    #[Test]
    #[Depends('create')]
    public function authority(ChargingIdentityAttributeValue $value)
    {
        static::assertSame(self::AUTHORITY_DN, $value->policyAuthority()->firstDN()->toString());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(ChargingIdentityAttributeValue $value)
    {
        static::assertCount(3, $value);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(ChargingIdentityAttributeValue $value)
    {
        $values = [];
        foreach ($value as $val) {
            $values[] = $val;
        }
        static::assertCount(3, $values);
        static::assertContainsOnlyInstancesOf(IetfAttrValue::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function octetStringValue(ChargingIdentityAttributeValue $value)
    {
        static::assertSame(self::OCTETS_VAL, (string) ($value->values()[0]));
    }

    #[Test]
    #[Depends('create')]
    public function oIDValue(ChargingIdentityAttributeValue $value)
    {
        static::assertSame(self::OID_VAL, (string) ($value->values()[1]));
    }

    #[Test]
    #[Depends('create')]
    public function uTF8Value(ChargingIdentityAttributeValue $value)
    {
        static::assertSame(self::UTF8_VAL, (string) ($value->values()[2]));
    }

    #[Test]
    #[Depends('create')]
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasChargingIdentity());
        return $attribs;
    }

    #[Test]
    #[Depends('attributes')]
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(ChargingIdentityAttributeValue::class, $attribs->chargingIdentity());
    }
}
