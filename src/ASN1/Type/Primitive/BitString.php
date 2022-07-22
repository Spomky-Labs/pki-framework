<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Primitive;

use Brick\Math\BigInteger;
use function chr;
use function mb_strlen;
use function ord;
use OutOfBoundsException;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\BaseString;
use SpomkyLabs\Pki\ASN1\Type\PrimitiveType;
use SpomkyLabs\Pki\ASN1\Type\UniversalClass;

/**
 * Implements *BIT STRING* type.
 */
final class BitString extends BaseString
{
    use UniversalClass;
    use PrimitiveType;

    /**
     * @param string $string Content octets
     * @param int $_unusedBits Number of unused bits in the last octet
     */
    public function __construct(
        string $string,
        protected int $_unusedBits = 0
    ) {
        $this->typeTag = self::TYPE_BIT_STRING;
        parent::__construct($string);
    }

    /**
     * Get the number of bits in the string.
     */
    public function numBits(): int
    {
        return mb_strlen($this->_string, '8bit') * 8 - $this->_unusedBits;
    }

    /**
     * Get the number of unused bits in the last octet of the string.
     */
    public function unusedBits(): int
    {
        return $this->_unusedBits;
    }

    /**
     * Test whether bit is set.
     *
     * @param int $idx Bit index. Most significant bit of the first octet is index 0.
     */
    public function testBit(int $idx): bool
    {
        // octet index
        $oi = (int) floor($idx / 8);
        // if octet is outside range
        if ($oi < 0 || $oi >= mb_strlen($this->_string, '8bit')) {
            throw new OutOfBoundsException('Index is out of bounds.');
        }
        // bit index
        $bi = $idx % 8;
        // if tested bit is last octet's unused bit
        if ($oi === mb_strlen($this->_string, '8bit') - 1) {
            if ($bi >= 8 - $this->_unusedBits) {
                throw new OutOfBoundsException('Index refers to an unused bit.');
            }
        }
        $byte = $this->_string[$oi];
        // index 0 is the most significant bit in byte
        $mask = 0x01 << (7 - $bi);
        return (ord($byte) & $mask) > 0;
    }

    /**
     * Get range of bits.
     *
     * @param int $start Index of first bit
     * @param int $length Number of bits in range
     *
     * @return string Integer of $length bits
     */
    public function range(int $start, int $length): string
    {
        if (! $length) {
            return '0';
        }
        if ($start + $length > $this->numBits()) {
            throw new OutOfBoundsException('Not enough bits.');
        }
        $bits = BigInteger::of(0);
        $idx = $start;
        $end = $start + $length;
        while (true) {
            $bit = $this->testBit($idx) ? 1 : 0;
            $bits = $bits->or($bit);
            if (++$idx >= $end) {
                break;
            }
            $bits = $bits->shiftedLeft(1);
        }
        return $bits->toBase(10);
    }

    /**
     * Get a copy of the bit string with trailing zeroes removed.
     */
    public function withoutTrailingZeroes(): self
    {
        // if bit string was empty
        if (! mb_strlen($this->_string, '8bit')) {
            return new self('');
        }
        $bits = $this->_string;
        // count number of empty trailing octets
        $unused_octets = 0;
        for ($idx = mb_strlen($bits, '8bit') - 1; $idx >= 0; --$idx, ++$unused_octets) {
            if ($bits[$idx] !== "\x0") {
                break;
            }
        }
        // strip trailing octets
        if ($unused_octets) {
            $bits = mb_substr($bits, 0, -$unused_octets, '8bit');
        }
        // if bit string was full of zeroes
        if (! mb_strlen($bits, '8bit')) {
            return new self('');
        }
        // count number of trailing zeroes in the last octet
        $unused_bits = 0;
        $byte = ord($bits[mb_strlen($bits, '8bit') - 1]);
        while (! ($byte & 0x01)) {
            ++$unused_bits;
            $byte >>= 1;
        }
        return new self($bits, $unused_bits);
    }

    protected function encodedAsDER(): string
    {
        $der = chr($this->_unusedBits);
        $der .= $this->_string;
        if ($this->_unusedBits) {
            $octet = $der[mb_strlen($der, '8bit') - 1];
            // set unused bits to zero
            $octet &= chr(0xff & ~((1 << $this->_unusedBits) - 1));
            $der[mb_strlen($der, '8bit') - 1] = $octet;
        }
        return $der;
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        $idx = $offset;
        $length = Length::expectFromDER($data, $idx);
        if ($length->intLength() < 1) {
            throw new DecodeException('Bit string length must be at least 1.');
        }
        $unused_bits = ord($data[$idx++]);
        if ($unused_bits > 7) {
            throw new DecodeException('Unused bits in a bit string must be less than 8.');
        }
        $str_len = $length->intLength() - 1;
        if ($str_len) {
            $str = mb_substr($data, $idx, $str_len, '8bit');
            if ($unused_bits) {
                $mask = (1 << $unused_bits) - 1;
                if (ord($str[mb_strlen($str, '8bit') - 1]) & $mask) {
                    throw new DecodeException('DER encoded bit string must have zero padding.');
                }
            }
        } else {
            $str = '';
        }
        $offset = $idx + $str_len;
        return new self($str, $unused_bits);
    }
}
