<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *PrintableString* type.
 */
final class PrintableString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->typeTag = self::TYPE_PRINTABLE_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        $chars = preg_quote(" '()+,-./:=?]", '/');
        return preg_match('/[^A-Za-z0-9' . $chars . ']/', $string) !== 1;
    }
}
