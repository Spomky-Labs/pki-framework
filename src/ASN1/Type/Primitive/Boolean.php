<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use function chr;
use function ord;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\PrimitiveType;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *BOOLEAN* type.
 */
final class Boolean extends Element
{
    use UniversalClass;
    use PrimitiveType;

    public function __construct(
        private readonly bool $_bool
    ) {
        $this->typeTag = self::TYPE_BOOLEAN;
    }

    /**
     * Get the value.
     */
    public function value(): bool
    {
        return $this->_bool;
    }

    protected function encodedAsDER(): string
    {
        return $this->_bool ? chr(0xff) : chr(0);
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        Length::expectFromDER($data, $idx, 1);
        $byte = ord($data[$idx++]);
        if ($byte !== 0) {
            if ($byte !== 0xff) {
                throw new DecodeException('DER encoded boolean true must have all bits set to 1.');
            }
        }
        $offset = $idx;
        return new self($byte !== 0);
    }
}
