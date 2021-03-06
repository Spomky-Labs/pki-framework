<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash;

use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/*
From RFC 3370 - 2.1 SHA-1

    The AlgorithmIdentifier parameters field is OPTIONAL.  If present,
    the parameters field MUST contain a NULL.  Implementations MUST
    accept SHA-1 AlgorithmIdentifiers with absent parameters.
    Implementations MUST accept SHA-1 AlgorithmIdentifiers with NULL
    parameters.  Implementations SHOULD generate SHA-1
    AlgorithmIdentifiers with absent parameters.
 */

/**
 * SHA-1 algorithm identifier.
 *
 * @see http://oid-info.com/get/1.3.14.3.2.26
 * @see https://tools.ietf.org/html/rfc3370#section-2.1
 */
final class SHA1AlgorithmIdentifier extends SpecificAlgorithmIdentifier implements HashAlgorithmIdentifier
{
    /**
     * Parameters.
     */
    protected ?NullType $_params;

    public function __construct()
    {
        $this->oid = self::OID_SHA1;
        $this->_params = null;
    }

    public function name(): string
    {
        return 'sha1';
    }

    /**
     * @return self
     */
    public static function fromASN1Params(?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        $obj = new static();
        // if parameters field is present, it must be null type
        if (isset($params)) {
            $obj->_params = $params->asNull();
        }
        return $obj;
    }

    /**
     * @return null|NullType
     */
    protected function paramsASN1(): ?Element
    {
        return $this->_params;
    }
}
