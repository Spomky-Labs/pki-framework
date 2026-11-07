<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519;

use LogicException;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed25519AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;

/**
 * Implements an intermediary object to store Ed25519 private key.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
final class Ed25519PrivateKey extends Curve25519PrivateKey
{
    public static function create(string $private_key, ?string $public_key = null): self
    {
        return new self($private_key, $public_key);
    }

    /**
     * Initialize from `CurvePrivateKey` OctetString.
     *
     * @param OctetString $str Private key data wrapped into OctetString
     * @param null|string $public_key Optional public key data
     */
    public static function fromOctetString(OctetString $str, ?string $public_key = null): self
    {
        return self::create($str->string(), $public_key);
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return Ed25519AlgorithmIdentifier::create();
    }

    /**
     * Get the public key, derived from the private key when the structure does not embed it.
     *
     * @throws LogicException If the public key is not embedded and this runtime cannot derive it
     */
    public function publicKey(): PublicKey
    {
        return Ed25519PublicKey::create($this->publicKeyBytes());
    }
}
