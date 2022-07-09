<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\Asymmetric\RFC8410\Curve448;

use function mb_strlen;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\X448AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use Sop\CryptoTypes\Asymmetric\RFC8410\RFC8410PublicKey;
use UnexpectedValueException;

/**
 * Implements an intermediary class to store X448 public key.
 *
 * @see https://tools.ietf.org/html/rfc8410
 */
final class X448PublicKey extends RFC8410PublicKey
{
    /**
     * Constructor.
     *
     * @param string $public_key Public key data
     */
    public function __construct(string $public_key)
    {
        if (56 !== mb_strlen($public_key, '8bit')) {
            throw new UnexpectedValueException('X448 public key must be exactly 56 bytes.');
        }
        parent::__construct($public_key);
    }

    public function algorithmIdentifier(): AlgorithmIdentifierType
    {
        return new X448AlgorithmIdentifier();
    }
}
