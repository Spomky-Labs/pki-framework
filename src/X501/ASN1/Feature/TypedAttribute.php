<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\ASN1\Feature;

use SpomkyLabs\Pki\X501\ASN1\AttributeType;

/**
 * Trait for attributes having a type.
 */
trait TypedAttribute
{
    /**
     * Attribute type.
     *
     * @var AttributeType
     */
    protected $_type;

    /**
     * Get attribute type.
     */
    public function type(): AttributeType
    {
        return $this->_type;
    }

    /**
     * Get OID of the attribute.
     */
    public function oid(): string
    {
        return $this->_type->oid();
    }
}
