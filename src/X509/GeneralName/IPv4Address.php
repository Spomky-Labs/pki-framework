<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use function array_slice;
use function count;
use UnexpectedValueException;

final class IPv4Address extends IPAddress
{
    /**
     * Initialize from octets.
     */
    public static function fromOctets(string $octets): self
    {
        $mask = null;
        $bytes = unpack('C*', $octets);
        $bytes = $bytes === false ? [] : $bytes;
        switch (count($bytes)) {
            case 4:
                $ip = implode('.', $bytes);
                break;
            case 8:
                $ip = implode('.', array_slice($bytes, 0, 4));
                $mask = implode('.', array_slice($bytes, 4, 4));
                break;
            default:
                throw new UnexpectedValueException('Invalid IPv4 octet length.');
        }
        return new self($ip, $mask);
    }

    protected function _octets(): string
    {
        $bytes = array_map('intval', explode('.', $this->_ip));
        if (isset($this->_mask)) {
            $bytes = array_merge($bytes, array_map('intval', explode('.', $this->_mask)));
        }
        return pack('C*', ...$bytes);
    }
}
