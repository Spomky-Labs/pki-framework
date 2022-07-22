<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature;

use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * RSA with SHA-256 signature algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc4055#section-5
 */
final class SHA256WithRSAEncryptionAlgorithmIdentifier extends RFC4055RSASignatureAlgorithmIdentifier
{
    private function __construct()
    {
        parent::__construct();
        $this->oid = self::OID_SHA256_WITH_RSA_ENCRYPTION;
    }

    public static function create(): self
    {
        return new self();
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): self
    {
        $obj = new self();
        // store parameters so re-encoding doesn't change
        if (isset($params)) {
            $obj->params = $params->asElement();
        }
        return $obj;
    }

    public function name(): string
    {
        return 'sha256WithRSAEncryption';
    }
}
