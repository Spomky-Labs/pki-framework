<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448;

use function mb_strlen;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\X448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\RFC8410PublicKey;
use UnexpectedValueException;

/**
 * Implements an intermediary class to store X448 public key.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
final class X448PublicKey extends RFC8410PublicKey
{
    /**
     * @param string $public_key Public key data
     */
    public function __construct(string $public_key)
    {
        if (mb_strlen($public_key, '8bit') !== 56) {
            throw new UnexpectedValueException('X448 public key must be exactly 56 bytes.');
        }
        parent::__construct($public_key);
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return X448AlgorithmIdentifier::create();
    }
}
