<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use UnexpectedValueException;

/*
From RFC 3447:

    When rsaEncryption is used in an AlgorithmIdentifier the
    parameters MUST be present and MUST be NULL.
 */

/**
 * Algorithm identifier for RSA encryption.
 *
 * @see http://www.oid-info.com/get/1.2.840.113549.1.1.1
 * @see https://tools.ietf.org/html/rfc3447#appendix-C
 */
final class RSAEncryptionAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements AsymmetricCryptoAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_RSA_ENCRYPTION;
    }

    public function name(): string
    {
        return 'rsaEncryption';
    }

    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        if (! isset($params)) {
            throw new UnexpectedValueException('No parameters.');
        }
        $params->asNull();
        return new self();
    }

    /**
     * @return NullType
     */
    protected function _paramsASN1(): ?Element
    {
        return new NullType();
    }
}
