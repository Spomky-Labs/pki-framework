<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\ASN1\AttributeValue;

use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\DirectoryString;

/**
 * 'organizationalUnitName' attribute value.
 *
 * @see https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html#SelectedAttributeTypes.organizationalUnitName
 */
final class OrganizationalUnitNameValue extends DirectoryString
{
    /**
     * @param string $value String value
     * @param int $string_tag Syntax choice
     */
    protected function __construct(string $value, int $string_tag = DirectoryString::UTF8)
    {
        $this->_oid = AttributeType::OID_ORGANIZATIONAL_UNIT_NAME;
        parent::__construct($value, $string_tag);
    }

    public static function create(string $value, int $string_tag = DirectoryString::UTF8): self
    {
        return new self($value, $string_tag);
    }
}
