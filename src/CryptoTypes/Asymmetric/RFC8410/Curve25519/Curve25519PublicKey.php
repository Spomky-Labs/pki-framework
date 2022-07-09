<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\Asymmetric\RFC8410\Curve25519;

use function mb_strlen;
use Sop\CryptoTypes\Asymmetric\RFC8410\RFC8410PublicKey;
use UnexpectedValueException;

/**
 * Implements an intermediary object to store a public key using Curve25519.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
abstract class Curve25519PublicKey extends RFC8410PublicKey
{
    /**
     * Constructor.
     *
     * @param string $public_key Public key data
     */
    public function __construct(string $public_key)
    {
        if (mb_strlen($public_key, '8bit') !== 32) {
            throw new UnexpectedValueException('Curve25519 public key must be exactly 32 bytes.');
        }
        parent::__construct($public_key);
    }
}
