<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;

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
    protected null|Element $params;

    protected function __construct(string $oid)
    {
        parent::__construct($oid);
        $this->params = NullType::create();
    }

    protected function paramsASN1(): ?Element
    {
        return $this->params;
    }
}
