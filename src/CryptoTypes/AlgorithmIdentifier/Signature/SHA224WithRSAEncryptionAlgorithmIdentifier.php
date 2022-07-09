<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\AlgorithmIdentifier\Signature;

/**
 * RSA with SHA-224 signature algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc4055#section-5
 */
final class SHA224WithRSAEncryptionAlgorithmIdentifier extends RFC4055RSASignatureAlgorithmIdentifier
{
    public function __construct()
    {
        parent::__construct();
        $this->_oid = self::OID_SHA224_WITH_RSA_ENCRYPTION;
    }

    public function name(): string
    {
        return 'sha224WithRSAEncryption';
    }
}
