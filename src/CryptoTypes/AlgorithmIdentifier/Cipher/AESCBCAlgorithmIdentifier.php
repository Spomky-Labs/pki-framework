<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;

/*
From RFC 3565 - 4.1. AES Algorithm Identifiers and Parameters:

The AlgorithmIdentifier parameters field MUST be present, and the parameter field MUST contain a AES-IV:

    AES-IV ::= OCTET STRING (SIZE(16))
 */

/**
 * Base class for AES-CBC algorithm identifiers.
 *
 * @see https://tools.ietf.org/html/rfc3565.html#section-4.1
 */
abstract class AESCBCAlgorithmIdentifier extends BlockCipherAlgorithmIdentifier
{
    /**
     * @param string $iv Initialization vector
     */
    protected function __construct(string $iod, string $iv)
    {
        $this->_checkIVSize($iv);
        parent::__construct($iod, $iv);
    }

    public function blockSize(): int
    {
        return 16;
    }

    public function ivSize(): int
    {
        return 16;
    }

    /**
     * @return OctetString
     */
    protected function paramsASN1(): ?Element
    {
        if (! isset($this->_initializationVector)) {
            throw new LogicException('IV not set.');
        }
        return OctetString::create($this->_initializationVector);
    }
}
