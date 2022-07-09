<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Signature;

use InvalidArgumentException;
use function mb_strlen;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;

/**
 * Implements Ed25519 signature value.
 *
 * @todo Implement signature parsing
 *
 * @see https://tools.ietf.org/html/rfc8032#section-5.1.6
 */
final class Ed25519Signature extends Signature
{
    /**
     * Signature value.
     */
    private readonly string $_signature;

    public function __construct(string $signature)
    {
        if (mb_strlen($signature, '8bit') !== 64) {
            throw new InvalidArgumentException('Ed25519 signature must be 64 octets.');
        }
        $this->_signature = $signature;
    }

    public function bitString(): BitString
    {
        return new BitString($this->_signature);
    }
}
