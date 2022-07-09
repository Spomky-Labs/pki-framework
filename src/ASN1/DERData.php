<?php

declare(strict_types=1);

namespace Sop\ASN1;

use function mb_strlen;
use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Component\Length;

/**
 * Container for raw DER encoded data.
 *
 * May be inserted into structure without decoding first.
 */
class DERData extends Element
{
    /**
     * DER encoded data.
     *
     * @var string
     */
    protected $_der;

    /**
     * Identifier of the underlying type.
     *
     * @var Identifier
     */
    protected $_identifier;

    /**
     * Offset to the content in DER data.
     *
     * @var int
     */
    protected $_contentOffset = 0;

    /**
     * Constructor.
     *
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

    protected function _encodedContentDER(): string
    {
        // if there's no content payload
        if (mb_strlen($this->_der, '8bit') === $this->_contentOffset) {
            return '';
        }
        return mb_substr($this->_der, $this->_contentOffset, null, '8bit');
    }
}
