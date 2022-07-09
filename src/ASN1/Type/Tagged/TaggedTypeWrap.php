<?php

declare(strict_types=1);

namespace Sop\ASN1\Type\Tagged;

use Sop\ASN1\Element;
use Sop\ASN1\Type\TaggedType;

/**
 * Base class to wrap inner element for tagging.
 */
abstract class TaggedTypeWrap extends TaggedType
{
    /**
     * Wrapped element.
     *
     * @var Element
     */
    protected $_element;

    /**
     * Type class.
     *
     * @var int
     */
    protected $_class;

    public function typeClass(): int
    {
        return $this->_class;
    }
}
