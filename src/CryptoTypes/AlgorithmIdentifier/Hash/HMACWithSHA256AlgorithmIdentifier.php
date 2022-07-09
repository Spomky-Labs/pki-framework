<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash;

/**
 * HMAC with SHA-256 algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc4231#section-3.1
 */
final class HMACWithSHA256AlgorithmIdentifier extends RFC4231HMACAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_HMAC_WITH_SHA256;
    }

    public function name(): string
    {
        return 'hmacWithSHA256';
    }
}
