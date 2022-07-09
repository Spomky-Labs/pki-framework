<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\ASN1;

use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\Feature\TypedAttribute;
use Stringable;

/**
 * Implements *AttributeTypeAndValue* ASN.1 type.
 *
 * @see https://www.itu.int/ITU-T/formal-language/itu-t/x/x501/2012/InformationFramework.html#InformationFramework.AttributeTypeAndValue
 */
final class AttributeTypeAndValue implements Stringable
{
    use TypedAttribute;

    /**
     * Constructor.
     *
     * @param AttributeType  $type  Attribute type
     * @param AttributeValue $_value Attribute value
     */
    public function __construct(
        AttributeType $type,
        protected AttributeValue $_value
    ) {
        $this->_type = $type;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $type = AttributeType::fromASN1($seq->at(0)->asObjectIdentifier());
        $value = AttributeValue::fromASN1ByOID($type->oid(), $seq->at(1));
        return new self($type, $value);
    }

    /**
     * Convenience method to initialize from attribute value.
     *
     * @param AttributeValue $value Attribute value
     */
    public static function fromAttributeValue(AttributeValue $value): self
    {
        return new self(new AttributeType($value->oid()), $value);
    }

    /**
     * Get attribute value.
     */
    public function value(): AttributeValue
    {
        return $this->_value;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        return new Sequence($this->_type->toASN1(), $this->_value->toASN1());
    }

    /**
     * Get attributeTypeAndValue string conforming to RFC 2253.
     *
     * @see https://tools.ietf.org/html/rfc2253#section-2.3
     */
    public function toString(): string
    {
        return $this->_type->typeName() . '=' . $this->_value->rfc2253String();
    }

    /**
     * Check whether attribute is semantically equal to other.
     *
     * @param AttributeTypeAndValue $other Object to compare to
     */
    public function equals(self $other): bool
    {
        // check that attribute types match
        if ($this->oid() !== $other->oid()) {
            return false;
        }
        $matcher = $this->_value->equalityMatchingRule();
        $result = $matcher->compare($this->_value->stringValue(), $other->_value->stringValue());
        // match
        if ($result) {
            return true;
        }
        // no match or Undefined
        return false;
    }
}
