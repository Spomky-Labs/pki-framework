<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac\Attribute;

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

    /**
     * @test
     */
    public function create()
    {
        $value = new ChargingIdentityAttributeValue(
            IetfAttrValue::fromOctets(self::OCTETS_VAL),
            IetfAttrValue::fromOID(self::OID_VAL),
            IetfAttrValue::fromString(self::UTF8_VAL)
        );
        $value = $value->withPolicyAuthority(new GeneralNames(DirectoryName::fromDNString(self::AUTHORITY_DN)));
        static::assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
        $value = ChargingIdentityAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        static::assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
        static::assertEquals(ChargingIdentityAttributeValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function authority(ChargingIdentityAttributeValue $value)
    {
        static::assertEquals(self::AUTHORITY_DN, $value->policyAuthority() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(ChargingIdentityAttributeValue $value)
    {
        static::assertCount(3, $value);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(ChargingIdentityAttributeValue $value)
    {
        $values = [];
        foreach ($value as $val) {
            $values[] = $val;
        }
        static::assertCount(3, $values);
        static::assertContainsOnlyInstancesOf(IetfAttrValue::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function octetStringValue(ChargingIdentityAttributeValue $value)
    {
        static::assertEquals(self::OCTETS_VAL, $value->values()[0]);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oIDValue(ChargingIdentityAttributeValue $value)
    {
        static::assertEquals(self::OID_VAL, $value->values()[1]);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function uTF8Value(ChargingIdentityAttributeValue $value)
    {
        static::assertEquals(self::UTF8_VAL, $value->values()[2]);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        static::assertTrue($attribs->hasChargingIdentity());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        static::assertInstanceOf(ChargingIdentityAttributeValue::class, $attribs->chargingIdentity());
    }
}
