<?php

declare(strict_types=1);

namespace Sop\CryptoTypes\Signature;

use InvalidArgumentException;
use Sop\ASN1\Type\Primitive\BitString;
use function strlen;

/**
 * Implements Ed25519 signature value.
 *
 * @todo Implement signature parsing
 *
 * @see https://tools.ietf.org/html/rfc8032#section-5.1.6
 */
class Ed25519Signature extends Signature
{
    /**
     * Signature value.
     *
     * @var string
     */
    private $_signature;

    /**
     * Constructor.
     */
    public function __construct(string $signature)
    {
        if (64 !== strlen($signature)) {
            throw new InvalidArgumentException('Ed25519 signature must be 64 octets.');
        }
        $this->_signature = $signature;
    }

    public function bitString(): BitString
    {
        return new BitString($this->_signature);
    }
}
