<?php

declare(strict_types=1);

namespace Sop\X509\GeneralName;

use function array_slice;
use function count;
use UnexpectedValueException;

class IPv6Address extends IPAddress
{
    /**
     * Initialize from octets.
     */
    public static function fromOctets(string $octets): self
    {
        $mask = null;
        $words = unpack('n*', $octets) ?: [];
        switch (count($words)) {
            case 8:
                $ip = self::_wordsToIPv6String($words);
                break;
            case 16:
                $ip = self::_wordsToIPv6String(array_slice($words, 0, 8));
                $mask = self::_wordsToIPv6String(array_slice($words, 8, 8));
                break;
            default:
                throw new UnexpectedValueException('Invalid IPv6 octet length.');
        }
        return new self($ip, $mask);
    }

    /**
     * Convert an array of 16 bit words to an IPv6 string representation.
     *
     * @param int[] $words
     */
    protected static function _wordsToIPv6String(array $words): string
    {
        $groups = array_map(fn ($word) => sprintf('%04x', $word), $words);
        return implode(':', $groups);
    }

    protected function _octets(): string
    {
        $words = array_map('hexdec', explode(':', $this->_ip));
        if (isset($this->_mask)) {
            $words = array_merge($words, array_map('hexdec', explode(':', $this->_mask)));
        }
        return pack('n*', ...$words);
    }
}
