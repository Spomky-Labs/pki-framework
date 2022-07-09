<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *PrintableString* type.
 */
class PrintableString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_PRINTABLE_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        $chars = preg_quote(" '()+,-./:=?]", '/');
        return 1 !== preg_match('/[^A-Za-z0-9' . $chars . ']/', $string);
    }
}
