<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Tagged;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;

/**
 * Base class to wrap inner element for tagging.
 */
abstract class TaggedTypeWrap extends TaggedType
{
    public function __construct(
        protected Element $_element,
        protected int $_class,
        int $typeTag
    ) {
        parent::__construct($typeTag);
    }

    public function typeClass(): int
    {
        return $this->_class;
    }
}
