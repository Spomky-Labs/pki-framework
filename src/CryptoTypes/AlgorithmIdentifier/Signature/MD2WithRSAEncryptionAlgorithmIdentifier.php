<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature;

/**
 * RSA with MD2 signature algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc3279#section-2.2.1
 */
final class MD2WithRSAEncryptionAlgorithmIdentifier extends RFC3279RSASignatureAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_MD2_WITH_RSA_ENCRYPTION;
    }

    public function name(): string
    {
        return 'md2WithRSAEncryption';
    }
}
