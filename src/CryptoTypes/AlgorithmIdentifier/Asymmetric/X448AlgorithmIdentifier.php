<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric;

/**
 * Algorithm identifier for the Diffie-Hellman operation with curve448.
 *
 * @see http://oid-info.com/get/1.3.101.111
 */
final class X448AlgorithmIdentifier extends RFC8410XAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_X448;
    }

    public function name(): string
    {
        return 'id-X448';
    }
}
