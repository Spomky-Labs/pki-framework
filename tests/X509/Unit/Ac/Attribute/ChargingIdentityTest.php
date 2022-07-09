<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac\Attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X509\AttributeCertificate\Attribute\ChargingIdentityAttributeValue;
use Sop\X509\AttributeCertificate\Attribute\IetfAttrValue;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

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
        $this->assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
        $value = ChargingIdentityAttributeValue::fromASN1(Sequence::fromDER($der)->asUnspecified());
        $this->assertInstanceOf(ChargingIdentityAttributeValue::class, $value);
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
        $this->assertEquals(ChargingIdentityAttributeValue::OID, $value->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function authority(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::AUTHORITY_DN, $value->policyAuthority() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(ChargingIdentityAttributeValue $value)
    {
        $this->assertCount(3, $value);
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
        $this->assertCount(3, $values);
        $this->assertContainsOnlyInstancesOf(IetfAttrValue::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function octetStringValue(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::OCTETS_VAL, $value->values()[0]);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oIDValue(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::OID_VAL, $value->values()[1]);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function uTF8Value(ChargingIdentityAttributeValue $value)
    {
        $this->assertEquals(self::UTF8_VAL, $value->values()[2]);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attributes(AttributeValue $value)
    {
        $attribs = Attributes::fromAttributeValues($value);
        $this->assertTrue($attribs->hasChargingIdentity());
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @test
     */
    public function fromAttributes(Attributes $attribs)
    {
        $this->assertInstanceOf(ChargingIdentityAttributeValue::class, $attribs->chargingIdentity());
    }
}
