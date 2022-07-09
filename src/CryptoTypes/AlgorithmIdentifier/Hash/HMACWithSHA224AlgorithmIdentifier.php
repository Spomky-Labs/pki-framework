<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\AlgorithmIdentifier\Hash;

/**
 * HMAC with SHA-224 algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc4231#section-3.1
 */
final class HMACWithSHA224AlgorithmIdentifier extends RFC4231HMACAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_HMAC_WITH_SHA224;
    }

    public function name(): string
    {
        return 'hmacWithSHA224';
    }
}
