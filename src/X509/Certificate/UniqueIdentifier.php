<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate;

use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;

/**
 * Implements *UniqueIdentifier* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1.2.8
 */
final class UniqueIdentifier
{
    public function __construct(
        /**
         * Identifier.
         */
        protected BitString $_uid
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(BitString $bs): self
    {
        return new self($bs);
    }

    /**
     * Initialize from string.
     */
    public static function fromString(string $str): self
    {
        return new self(new BitString($str));
    }

    /**
     * Get unique identifier as a string.
     */
    public function string(): string
    {
        return $this->_uid->string();
    }

    /**
     * Get unique identifier as a bit string.
     */
    public function bitString(): BitString
    {
        return $this->_uid;
    }

    /**
     * Get ASN.1 element.
     */
    public function toASN1(): BitString
    {
        return $this->_uid;
    }
}
