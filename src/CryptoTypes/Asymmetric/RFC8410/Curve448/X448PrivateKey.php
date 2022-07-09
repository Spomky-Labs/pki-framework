<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\Asymmetric\RFC8410\Curve448;

use LogicException;
use function mb_strlen;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\X448AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use Sop\CryptoTypes\Asymmetric\PublicKey;
use Sop\CryptoTypes\Asymmetric\RFC8410\RFC8410PrivateKey;
use UnexpectedValueException;

/**
 * Implements an intermediary class to store X448 private key.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
class X448PrivateKey extends RFC8410PrivateKey
{
    /**
     * Constructor.
     *
     * @param string      $private_key Private key data
     * @param null|string $public_key  Public key data
     */
    public function __construct(string $private_key, ?string $public_key = null)
    {
        if (56 !== mb_strlen($private_key, '8bit')) {
            throw new UnexpectedValueException('X448 private key must be exactly 56 bytes.');
        }
        if (isset($public_key) && 56 !== mb_strlen($public_key, '8bit')) {
            throw new UnexpectedValueException('X448 public key must be exactly 56 bytes.');
        }
        parent::__construct($private_key, $public_key);
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new X448AlgorithmIdentifier();
    }

    public function publicKey(): PublicKey
    {
        if (! $this->hasPublicKey()) {
            throw new LogicException('Public key not set.');
        }
        return new X448PublicKey($this->_publicKeyData);
    }
}
