<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use UnexpectedValueException;

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
     * @param null|string $iv Initialization vector
     */
    public function __construct(?string $iv = null)
    {
        $this->_checkIVSize($iv);
        $this->_initializationVector = $iv;
    }

    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (! isset($params)) {
            throw new UnexpectedValueException('No parameters.');
        }
        $iv = $params->asOctetString()
            ->string();
        return new static($iv);
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
    protected function _paramsASN1(): ?Element
    {
        if (! isset($this->_initializationVector)) {
            throw new LogicException('IV not set.');
        }
        return new OctetString($this->_initializationVector);
    }
}
