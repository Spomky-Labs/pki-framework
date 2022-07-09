<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

/**
 * Implements *ENUMERATED* type.
 */
final class Enumerated extends Integer
{
    /**
     * Constructor.
     *
     * @param int|string $number
     */
    public function __construct($number)
    {
        parent::__construct($number);
        $this->_typeTag = self::TYPE_ENUMERATED;
    }
}
