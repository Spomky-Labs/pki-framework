<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use SpomkyLabs\Pki\ASN1\Type\PrimitiveString;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *ObjectDescriptor* type.
 */
final class ObjectDescriptor extends PrimitiveString
{
    use UniversalClass;

    public function __construct(string $descriptor)
    {
        $this->_string = $descriptor;
        $this->_typeTag = self::TYPE_OBJECT_DESCRIPTOR;
    }

    /**
     * Get the object descriptor.
     */
    public function descriptor(): string
    {
        return $this->_string;
    }
}
