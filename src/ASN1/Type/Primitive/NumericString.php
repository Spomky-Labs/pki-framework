<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *NumericString* type.
 */
final class NumericString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->typeTag = self::TYPE_NUMERIC_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        return preg_match('/[^\d ]/', $string) !== 1;
    }
}
