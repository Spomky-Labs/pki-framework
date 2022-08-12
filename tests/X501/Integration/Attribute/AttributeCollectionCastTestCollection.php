<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Attribute;

use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\Collection\SequenceOfAttributes;

final class AttributeCollectionCastTestCollection extends SequenceOfAttributes
{
    /**
     * Initialize from attribute values.
     *
     * @param AttributeValue ...$values List of attribute values
     */
    public static function fromAttributeValues(AttributeValue ...$values): static
    {
        return static::create(...array_map(fn (AttributeValue $value) => $value->toAttribute(), $values));
    }

    protected static function _castAttributeValues(Attribute $attribute): Attribute
    {
        return $attribute->oid() === '1.3.6.1.3' ?
            $attribute->castValues(AttributeCollectionCastTestAttrValue::class) :
            $attribute;
    }
}
