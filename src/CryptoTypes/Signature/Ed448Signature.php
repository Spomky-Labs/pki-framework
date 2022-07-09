<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\Signature;

use InvalidArgumentException;
use function mb_strlen;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;

/**
 * Implements Ed448 signature value.
 *
 * @todo Implement signature parsing
 *
 * @see https://tools.ietf.org/html/rfc8032#section-5.2.6
 */
final class Ed448Signature extends Signature
{
    /**
     * Signature value.
     */
    private readonly string $_signature;

    public function __construct(string $signature)
    {
        if (mb_strlen($signature, '8bit') !== 114) {
            throw new InvalidArgumentException('Ed448 signature must be 114 octets.');
        }
        $this->_signature = $signature;
    }

    public function bitString(): BitString
    {
        return new BitString($this->_signature);
    }
}
