<?php

declare(strict_types=1);

namespace integration\attribute;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\StringType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\X501\ASN1\AttributeType;
use Sop\X501\ASN1\AttributeValue\AttributeValue;
use Sop\X501\ASN1\AttributeValue\CommonNameValue;
use Sop\X501\ASN1\AttributeValue\CountryNameValue;
use Sop\X501\ASN1\AttributeValue\DescriptionValue;
use Sop\X501\ASN1\AttributeValue\GivenNameValue;
use Sop\X501\ASN1\AttributeValue\LocalityNameValue;
use Sop\X501\ASN1\AttributeValue\NameValue;
use Sop\X501\ASN1\AttributeValue\OrganizationalUnitNameValue;
use Sop\X501\ASN1\AttributeValue\OrganizationNameValue;
use Sop\X501\ASN1\AttributeValue\PseudonymValue;
use Sop\X501\ASN1\AttributeValue\SerialNumberValue;
use Sop\X501\ASN1\AttributeValue\StateOrProvinceNameValue;
use Sop\X501\ASN1\AttributeValue\SurnameValue;
use Sop\X501\ASN1\AttributeValue\TitleValue;

/**
 * @group asn1
 * @group value
 *
 * @internal
 */
class ValueInitializationTest extends TestCase
{
    /**
     * @dataProvider provideStringAttribClasses
     *
     * @param mixed $cls
     * @param mixed $oid
     */
    public function testCreate($cls, $oid)
    {
        $el = AttributeType::asn1StringForType($oid, 'Test');
        $val = AttributeValue::fromASN1ByOID($oid, new UnspecifiedType($el));
        $this->assertInstanceOf($cls, $val);
    }

    /**
     * @dataProvider provideStringAttribClasses
     *
     * @param mixed $cls
     * @param mixed $oid
     */
    public function testASN1($cls, $oid)
    {
        $val = new $cls('Test');
        $el = $val->toASN1();
        $this->assertInstanceOf(StringType::class, $el);
    }

    public function provideStringAttribClasses()
    {
        return [
            [CommonNameValue::class, AttributeType::OID_COMMON_NAME],
            [SurnameValue::class, AttributeType::OID_SURNAME],
            [SerialNumberValue::class, AttributeType::OID_SERIAL_NUMBER],
            [CountryNameValue::class, AttributeType::OID_COUNTRY_NAME],
            [LocalityNameValue::class, AttributeType::OID_LOCALITY_NAME],
            [StateOrProvinceNameValue::class, AttributeType::OID_STATE_OR_PROVINCE_NAME],
            [OrganizationNameValue::class, AttributeType::OID_ORGANIZATION_NAME],
            [OrganizationalUnitNameValue::class, AttributeType::OID_ORGANIZATIONAL_UNIT_NAME],
            [TitleValue::class, AttributeType::OID_TITLE],
            [DescriptionValue::class, AttributeType::OID_DESCRIPTION],
            [NameValue::class, AttributeType::OID_NAME],
            [GivenNameValue::class, AttributeType::OID_GIVEN_NAME],
            [PseudonymValue::class, AttributeType::OID_PSEUDONYM],
        ];
    }
}
