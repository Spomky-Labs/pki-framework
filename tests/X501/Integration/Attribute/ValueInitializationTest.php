<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\StringType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CountryNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\DescriptionValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\GivenNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\LocalityNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\NameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\OrganizationalUnitNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\OrganizationNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\PseudonymValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\SerialNumberValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\StateOrProvinceNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\SurnameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\TitleValue;

/**
 * @internal
 */
final class ValueInitializationTest extends TestCase
{
    #[Test]
    #[DataProvider('provideStringAttribClasses')]
    public function create(string $class, string $oid): void
    {
        $el = AttributeType::asn1StringForType($oid, 'Test');
        $val = AttributeValue::fromASN1ByOID($oid, UnspecifiedType::create($el));
        static::assertInstanceOf($class, $val);

        $val = $class::create('Test');
        $el = $val->toASN1();
        static::assertInstanceOf(StringType::class, $el);
    }

    public static function provideStringAttribClasses(): Iterator
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
