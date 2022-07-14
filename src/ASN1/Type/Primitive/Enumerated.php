<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use Brick\Math\BigInteger;

/**
 * Implements *ENUMERATED* type.
 */
final class Enumerated extends Integer
{
    public function __construct(BigInteger|int|string $number)
    {
        parent::__construct($number);
        $this->_typeTag = self::TYPE_ENUMERATED;
    }
}
