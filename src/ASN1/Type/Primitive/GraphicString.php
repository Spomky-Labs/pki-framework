<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *GraphicString* type.
 */
final class GraphicString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_GRAPHIC_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        // allow everything
        return true;
    }
}
