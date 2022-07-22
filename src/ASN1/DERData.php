<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1;

use BadMethodCallException;
use function mb_strlen;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;

/**
 * Container for raw DER encoded data.
 *
 * May be inserted into structure without decoding first.
 */
final class DERData extends Element
{
    /**
     * DER encoded data.
     */
    protected string $_der;

    /**
     * Identifier of the underlying type.
     */
    protected Identifier $_identifier;

    /**
     * Offset to the content in DER data.
     */
    protected int $_contentOffset = 0;

    /**
     * @param string $data DER encoded data
     */
    public function __construct(string $data)
    {
        $this->_identifier = Identifier::fromDER($data, $this->_contentOffset);
        // check that length encoding is valid
        Length::expectFromDER($data, $this->_contentOffset);
        $this->_der = $data;
        $this->_typeTag = $this->_identifier->intTag();
    }

    public function typeClass(): int
    {
        return $this->_identifier->typeClass();
    }

    public function isConstructed(): bool
    {
        return $this->_identifier->isConstructed();
    }

    public function toDER(): string
    {
        return $this->_der;
    }

    protected function encodedAsDER(): string
    {
        // if there's no content payload
        if (mb_strlen($this->_der, '8bit') === $this->_contentOffset) {
            return '';
        }
        return mb_substr($this->_der, $this->_contentOffset, null, '8bit');
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        throw new BadMethodCallException(__METHOD__ . ' must be implemented in derived class.');
    }
}
