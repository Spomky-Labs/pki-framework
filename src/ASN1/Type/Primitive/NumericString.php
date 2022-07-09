<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *NumericString* type.
 */
final class NumericString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_NUMERIC_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        return preg_match('/[^0-9 ]/', $string) !== 1;
    }
}
