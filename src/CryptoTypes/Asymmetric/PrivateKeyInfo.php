<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric;

use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\Attribute\OneAsymmetricKeyAttributes;

/**
 * PrivateKeyInfo was first introduced in RFC 5208, but later refined as OneAsymmetricKey in RFC 5958 with backwards
 * compatibility.
 *
 * Thus `PrivateKeyInfo ::= OneAsymmetricKey`
 *
 * @see https://tools.ietf.org/html/rfc5208#section-5
 * @see https://tools.ietf.org/html/rfc5958#section-2
 */
final class PrivateKeyInfo extends OneAsymmetricKey
{
    public function __construct(
        AlgorithmIdentifierType $algo,
        string $key,
        ?OneAsymmetricKeyAttributes $attributes = null,
        ?BitString $public_key = null
    ) {
        parent::__construct($algo, $key, $attributes, $public_key);
        // PrivateKeyInfo has version 1 by default
        $this->version = parent::VERSION_1;
    }
}
