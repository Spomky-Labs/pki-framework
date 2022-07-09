<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *IA5String* type.
 */
final class IA5String extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_IA5_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        return preg_match('/[^\x00-\x7f]/', $string) !== 1;
    }
}
