<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519;

use LogicException;
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
    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new Ed25519AlgorithmIdentifier();
    }

    public function publicKey(): PublicKey
    {
        if (! $this->hasPublicKey()) {
            throw new LogicException('Public key not set.');
        }
        return new Ed25519PublicKey($this->_publicKeyData);
    }
}
