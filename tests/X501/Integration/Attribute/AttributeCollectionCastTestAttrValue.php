<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\DirectoryString;

final class AttributeCollectionCastTestAttrValue extends DirectoryString
{
    protected function __construct(string $str)
    {
        $this->_oid = '1.3.6.1.3';
        parent::__construct($str, self::UTF8);
    }

    public static function create(string $value, int $string_tag = DirectoryString::UTF8): self
    {
        return new self($value, $string_tag);
    }
}
