<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *IA5String* type.
 */
final class IA5String extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->typeTag = self::TYPE_IA5_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        return preg_match('/[^\x00-\x7f]/', $string) !== 1;
    }
}
