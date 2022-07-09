<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use function mb_strlen;
use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *BMPString* type.
 *
 * BMP stands for Basic Multilingual Plane. This is generally an Unicode string with UCS-2 encoding.
 */
final class BMPString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_BMP_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        // UCS-2 has fixed with of 2 octets (16 bits)
        if (mb_strlen($string, '8bit') % 2 !== 0) {
            return false;
        }
        return true;
    }
}
