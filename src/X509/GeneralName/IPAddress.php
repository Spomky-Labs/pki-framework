<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\GeneralName;

use LogicException;
use function mb_strlen;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * Implements *iPAddress* CHOICE type of *GeneralName*.
 *
 * Concrete classes `IPv4Address` and `IPv6Address` furthermore implement the parsing semantics.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 */
abstract class IPAddress extends GeneralName
{
    public function __construct(
        /**
         * IP address.
         */
        protected string $_ip, /**
     * Subnet mask.
     */
        protected ?string $_mask = null
    ) {
        $this->_tag = self::TAG_IP_ADDRESS;
    }

    /**
     * @return self
     */
    public static function fromChosenASN1(UnspecifiedType $el): GeneralName
    {
        $octets = $el->asOctetString()
            ->string();
        return match (mb_strlen($octets, '8bit')) {
            4, 8 => IPv4Address::fromOctets($octets),
            16, 32 => IPv6Address::fromOctets($octets),
            default => throw new UnexpectedValueException('Invalid octet length for IP address.'),
        };
    }

    public function string(): string
    {
        return $this->_ip . (isset($this->_mask) ? '/' . $this->_mask : '');
    }

    /**
     * Get IP address as a string.
     */
    public function address(): string
    {
        return $this->_ip;
    }

    /**
     * Check whether mask is present.
     */
    public function hasMask(): bool
    {
        return isset($this->_mask);
    }

    /**
     * Get subnet mask as a string.
     */
    public function mask(): string
    {
        if (! $this->hasMask()) {
            throw new LogicException('mask is not set.');
        }
        return $this->_mask;
    }

    /**
     * Get octet representation of the IP address.
     */
    abstract protected function _octets(): string;

    protected function _choiceASN1(): TaggedType
    {
        return new ImplicitlyTaggedType($this->_tag, new OctetString($this->_octets()));
    }
}
