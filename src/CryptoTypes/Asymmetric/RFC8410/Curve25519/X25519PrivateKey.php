<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519;

use LogicException;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\X25519AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;

/**
 * Implements an intermediary object to store X25519 private key.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
final class X25519PrivateKey extends Curve25519PrivateKey
{
    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new X25519AlgorithmIdentifier();
    }

    public function publicKey(): PublicKey
    {
        if (! $this->hasPublicKey()) {
            throw new LogicException('Public key not set.');
        }
        return new X25519PublicKey($this->_publicKeyData);
    }
}
