<?php

declare(strict_types=1);

namespace Sop\Test\X501\Integration\Attribute;

use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

class AttributeCollectionCastTestCollection extends SequenceOfAttributes
{
    protected static function _castAttributeValues(Attribute $attribute): Attribute
    {
        return '1.3.6.1.3' === $attribute->oid() ?
            $attribute->castValues(AttributeCollectionCastTest_AttrValue::class) :
            $attribute;
    }
}
