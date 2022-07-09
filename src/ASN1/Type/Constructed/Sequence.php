<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Constructed;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Structure;

/**
 * Implements *SEQUENCE* and *SEQUENCE OF* types.
 */
final class Sequence extends Structure
{
    /**
     * Constructor.
     *
     * @param Element ...$elements Any number of elements
     */
    public function __construct(Element ...$elements)
    {
        $this->_typeTag = self::TYPE_SEQUENCE;
        parent::__construct(...$elements);
    }
}
