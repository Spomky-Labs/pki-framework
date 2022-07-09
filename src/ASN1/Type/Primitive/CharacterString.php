<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Primitive;

use Sop\ASN1\Type\PrimitiveString;
use Sop\ASN1\Type\UniversalClass;

/**
 * Implements *CHARACTER STRING* type.
 */
final class CharacterString extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $string)
    {
        $this->_typeTag = self::TYPE_CHARACTER_STRING;
        parent::__construct($string);
    }
}
