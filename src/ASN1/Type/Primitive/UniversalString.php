<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use function mb_strlen;
use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *UniversalString* type.
 *
 * Universal string is an Unicode string with UCS-4 encoding.
 */
class UniversalString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_UNIVERSAL_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        // UCS-4 has fixed with of 4 octets (32 bits)
        if (0 !== mb_strlen($string, '8bit') % 4) {
            return false;
        }
        return true;
    }
}
