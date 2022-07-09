<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/*
From RFC 4055 - 5.  PKCS #1 Version 1.5 Signature Algorithm

   When any of these four object identifiers appears within an
   AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
   MUST accept the parameters being absent as well as present.
 */

/**
 * Base class for RSA signature algorithms specified in RFC 4055.
 *
 * @see https://tools.ietf.org/html/rfc4055#section-5
 */
abstract class RFC4055RSASignatureAlgorithmIdentifier extends RSASignatureAlgorithmIdentifier
{
    /**
     * Parameters.
     *
     * @var null|Element
     */
    protected $_params;

    public function __construct()
    {
        $this->_params = new NullType();
    }

    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        $obj = new static();
        // store parameters so re-encoding doesn't change
        if (isset($params)) {
            $obj->_params = $params->asElement();
        }
        return $obj;
    }

    protected function _paramsASN1(): ?Element
    {
        return $this->_params;
    }
}
