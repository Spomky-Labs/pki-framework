<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *UTF8String* type.
 *
 * UTF8String* is an Unicode string with UTF-8 encoding.
 */
final class UTF8String extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->typeTag = self::TYPE_UTF8_STRING;
        parent::__construct($string);
    }

    protected function _validateString(string $string): bool
    {
        return mb_check_encoding($string, 'UTF-8');
    }
}
