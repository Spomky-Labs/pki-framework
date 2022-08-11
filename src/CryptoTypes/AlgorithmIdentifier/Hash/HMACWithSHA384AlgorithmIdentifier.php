<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash;

use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * HMAC with SHA-384 algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc4231#section-3.1
 */
final class HMACWithSHA384AlgorithmIdentifier extends RFC4231HMACAlgorithmIdentifier
{
    private function __construct()
    {
        parent::__construct(self::OID_HMAC_WITH_SHA384);
    }

    public static function create(): self
    {
        return new self();
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): self
    {
        /*
         * RFC 4231 states that the "parameter" component SHOULD be present
         * but have type NULL.
         */
        $obj = new self();
        if ($params !== null) {
            $obj->params = $params->asNull();
        }
        return $obj;
    }

    public function name(): string
    {
        return 'hmacWithSHA384';
    }
}
