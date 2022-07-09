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
RFC 2898 defines parameters as follows:

{OCTET STRING (SIZE(8)) IDENTIFIED BY desCBC}
 */

/**
 * Algorithm identifier for DES cipher in CBC mode.
 *
 * @see http://www.alvestrand.no/objectid/1.3.14.3.2.7.html
 * @see http://www.oid-info.com/get/1.3.14.3.2.7
 * @see https://tools.ietf.org/html/rfc2898#appendix-C
 */
final class DESCBCAlgorithmIdentifier extends BlockCipherAlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param null|string $iv Initialization vector
     */
    public function __construct(?string $iv = null)
    {
        $this->_checkIVSize($iv);
        $this->_oid = self::OID_DES_CBC;
        $this->_initializationVector = $iv;
    }

    public function name(): string
    {
        return 'desCBC';
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
        return new self($iv);
    }

    public function blockSize(): int
    {
        return 8;
    }

    public function keySize(): int
    {
        return 8;
    }

    public function ivSize(): int
    {
        return 8;
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
