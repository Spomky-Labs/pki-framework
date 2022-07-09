<?php

declare(strict_types=1);

namespace Sop\Test\X501\Integration\Attribute;

use Sop\X501\ASN1\Attribute;
use Sop\X501\ASN1\Collection\SequenceOfAttributes;

final class AttributeCollectionCastTestCollection extends SequenceOfAttributes
{
    protected static function _castAttributeValues(Attribute $attribute): Attribute
    {
        return $attribute->oid() === '1.3.6.1.3' ?
            $attribute->castValues(AttributeCollectionCastTest_AttrValue::class) :
            $attribute;
    }
}
