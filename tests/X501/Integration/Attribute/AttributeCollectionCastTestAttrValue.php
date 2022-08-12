<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use SpomkyLabs\Pki\X501\ASN1\AttributeValue\Feature\DirectoryString;

final class AttributeCollectionCastTestAttrValue extends DirectoryString
{
    public static function create(string $value, int $string_tag = DirectoryString::UTF8): static
    {
        return new static('1.3.6.1.3', $value, $string_tag);
    }
}
