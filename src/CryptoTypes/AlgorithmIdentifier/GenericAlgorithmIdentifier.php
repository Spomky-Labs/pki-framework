<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\AlgorithmIdentifier;

use Sop\ASN1\Element;
use Sop\ASN1\Type\UnspecifiedType;

/**
 * Generic algorithm identifier to hold parameters as ASN.1 objects.
 */
final class GenericAlgorithmIdentifier extends AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string               $oid    Algorithm OID
     * @param null|UnspecifiedType $_params Parameters
     */
    public function __construct(
        string $oid,
        protected ?UnspecifiedType $_params = null
    ) {
        $this->_oid = $oid;
    }

    public function name(): string
    {
        return $this->_oid;
    }

    public function parameters(): ?UnspecifiedType
    {
        return $this->_params;
    }

    protected function _paramsASN1(): ?Element
    {
        return $this->_params ? $this->_params->asElement() : null;
    }
}
