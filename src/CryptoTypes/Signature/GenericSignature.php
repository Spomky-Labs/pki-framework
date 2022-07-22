<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Signature;

use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;

/**
 * Generic signature value container.
 */
final class GenericSignature extends Signature
{
    /**
     * @param BitString $_signature Signature value
     * @param AlgorithmIdentifierType $_signatureAlgorithm Algorithm identifier
     */
    public function __construct(
        private readonly BitString $_signature,
        private readonly AlgorithmIdentifierType $_signatureAlgorithm
    ) {
    }

    /**
     * Get the signature algorithm.
     */
    public function signatureAlgorithm(): AlgorithmIdentifierType
    {
        return $this->_signatureAlgorithm;
    }

    public function bitString(): BitString
    {
        return $this->_signature;
    }
}
