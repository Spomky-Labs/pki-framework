<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\ASN1\AttributeValue;

use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\PrintableStringValue;

/**
 * 'countryName' attribute value.
 *
 * @see https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html#SelectedAttributeTypes.countryName
 */
final class CountryNameValue extends PrintableStringValue
{
    /**
     * @param string $value String value
     */
    public function __construct(string $value)
    {
        $this->_oid = AttributeType::OID_COUNTRY_NAME;
        parent::__construct($value);
    }
}
