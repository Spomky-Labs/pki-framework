<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\AttributeCertificate\Attribute;

use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use Stringable;
use UnexpectedValueException;

/**
 * Implements *IetfAttrSyntax.values* ASN.1 CHOICE type.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.4
 */
final class IetfAttrValue implements Stringable
{
    public function __construct(
        /**
         * Value.
         */
        protected string $_value,
        /**
         * Element type tag.
         */
        protected int $_type
    ) {
    }

    public function __toString(): string
    {
        return $this->_value;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(UnspecifiedType $el): self
    {
        return match ($el->tag()) {
            Element::TYPE_OCTET_STRING, Element::TYPE_UTF8_STRING => new self($el->asString()->string(), $el->tag()),
            Element::TYPE_OBJECT_IDENTIFIER => new self($el->asObjectIdentifier()->oid(), $el->tag()),
            default => throw new UnexpectedValueException('Type ' . Element::tagToName($el->tag()) . ' not supported.'),
        };
    }

    /**
     * Initialize from octet string.
     */
    public static function fromOctets(string $octets): self
    {
        return new self($octets, Element::TYPE_OCTET_STRING);
    }

    /**
     * Initialize from UTF-8 string.
     */
    public static function fromString(string $str): self
    {
        return new self($str, Element::TYPE_UTF8_STRING);
    }

    /**
     * Initialize from OID.
     */
    public static function fromOID(string $oid): self
    {
        return new self($oid, Element::TYPE_OBJECT_IDENTIFIER);
    }

    /**
     * Get type tag.
     */
    public function type(): int
    {
        return $this->_type;
    }

    /**
     * Whether value type is octets.
     */
    public function isOctets(): bool
    {
        return $this->_type === Element::TYPE_OCTET_STRING;
    }

    /**
     * Whether value type is OID.
     */
    public function isOID(): bool
    {
        return $this->_type === Element::TYPE_OBJECT_IDENTIFIER;
    }

    /**
     * Whether value type is string.
     */
    public function isString(): bool
    {
        return $this->_type === Element::TYPE_UTF8_STRING;
    }

    public function value(): string
    {
        return $this->_value;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Element
    {
        return match ($this->_type) {
            Element::TYPE_OCTET_STRING => OctetString::create($this->_value),
            Element::TYPE_UTF8_STRING => UTF8String::create($this->_value),
            Element::TYPE_OBJECT_IDENTIFIER => ObjectIdentifier::create($this->_value),
            default => throw new LogicException('Type ' . Element::tagToName($this->_type) . ' not supported.'),
        };
    }
}
