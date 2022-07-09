<?php

declare(strict_types=1);

namespace Sop\Test\X501\Integration\Attribute;

use Iterator;
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
 * @internal
 */
final class ValueInitializationTest extends TestCase
{
    /**
     * @dataProvider provideStringAttribClasses
     *
     * @test
     */
    public function create($cls, $oid)
    {
        $el = AttributeType::asn1StringForType($oid, 'Test');
        $val = AttributeValue::fromASN1ByOID($oid, new UnspecifiedType($el));
        static::assertInstanceOf($cls, $val);
    }

    /**
     * @dataProvider provideStringAttribClasses
     *
     * @test
     */
    public function aSN1($cls, $oid)
    {
        $val = new $cls('Test');
        $el = $val->toASN1();
        static::assertInstanceOf(StringType::class, $el);
    }

    public function provideStringAttribClasses(): Iterator
    {
        yield [CommonNameValue::class, AttributeType::OID_COMMON_NAME];
        yield [SurnameValue::class, AttributeType::OID_SURNAME];
        yield [SerialNumberValue::class, AttributeType::OID_SERIAL_NUMBER];
        yield [CountryNameValue::class, AttributeType::OID_COUNTRY_NAME];
        yield [LocalityNameValue::class, AttributeType::OID_LOCALITY_NAME];
        yield [StateOrProvinceNameValue::class, AttributeType::OID_STATE_OR_PROVINCE_NAME];
        yield [OrganizationNameValue::class, AttributeType::OID_ORGANIZATION_NAME];
        yield [OrganizationalUnitNameValue::class, AttributeType::OID_ORGANIZATIONAL_UNIT_NAME];
        yield [TitleValue::class, AttributeType::OID_TITLE];
        yield [DescriptionValue::class, AttributeType::OID_DESCRIPTION];
        yield [NameValue::class, AttributeType::OID_NAME];
        yield [GivenNameValue::class, AttributeType::OID_GIVEN_NAME];
        yield [PseudonymValue::class, AttributeType::OID_PSEUDONYM];
    }
}
