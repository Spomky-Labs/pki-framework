<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric;

/**
 * Algorithm identifier for the Diffie-Hellman operation with curve25519.
 *
 * @see http://oid-info.com/get/1.3.101.110
 */
final class X25519AlgorithmIdentifier extends RFC8410XAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_X25519;
    }

    public function name(): string
    {
        return 'id-X25519';
    }
}
