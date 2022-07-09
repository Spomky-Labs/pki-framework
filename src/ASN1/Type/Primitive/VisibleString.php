<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *VisibleString* type.
 */
final class VisibleString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_VISIBLE_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        return preg_match('/[^\x20-\x7e]/', $string) !== 1;
    }
}
