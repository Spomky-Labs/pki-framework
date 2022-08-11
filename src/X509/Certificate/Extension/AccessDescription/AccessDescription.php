<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription;

use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

/**
 * Base class implementing *AccessDescription* ASN.1 type for 'Authority Information Access' and 'Subject Information
 * Access' certificate extensions.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.1
 */
abstract class AccessDescription
{
    /**
     * @param string $_accessMethod Access method OID
     * @param GeneralName $_accessLocation Access location
     */
    public function __construct(
        protected string $_accessMethod,
        protected GeneralName $_accessLocation
    ) {
    }

    /**
     * Initialize from ASN.1.
     */
    abstract public static function fromASN1(Sequence $seq): static;

    /**
     * Get the access method OID.
     */
    public function accessMethod(): string
    {
        return $this->_accessMethod;
    }

    /**
     * Get the access location.
     */
    public function accessLocation(): GeneralName
    {
        return $this->_accessLocation;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return Sequence::create(ObjectIdentifier::create($this->_accessMethod), $this->_accessLocation->toASN1());
    }
}
