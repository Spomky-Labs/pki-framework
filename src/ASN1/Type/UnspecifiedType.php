<?php

declare(strict_types=1);

namespace Sop\ASN1\Type;

use Sop\ASN1\Component\Identifier;
use Sop\ASN1\Element;
use Sop\ASN1\Feature\ElementBase;
use Sop\ASN1\Type\Constructed\ConstructedString;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Constructed\Set;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\BMPString;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\CharacterString;
use Sop\ASN1\Type\Primitive\Enumerated;
use Sop\ASN1\Type\Primitive\GeneralizedTime;
use Sop\ASN1\Type\Primitive\GeneralString;
use Sop\ASN1\Type\Primitive\GraphicString;
use Sop\ASN1\Type\Primitive\IA5String;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\NumericString;
use Sop\ASN1\Type\Primitive\ObjectDescriptor;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Primitive\PrintableString;
use Sop\ASN1\Type\Primitive\Real;
use Sop\ASN1\Type\Primitive\RelativeOID;
use Sop\ASN1\Type\Primitive\T61String;
use Sop\ASN1\Type\Primitive\UniversalString;
use Sop\ASN1\Type\Primitive\UTCTime;
use Sop\ASN1\Type\Primitive\UTF8String;
use Sop\ASN1\Type\Primitive\VideotexString;
use Sop\ASN1\Type\Primitive\VisibleString;
use Sop\ASN1\Type\Tagged\ApplicationType;
use Sop\ASN1\Type\Tagged\PrivateType;
use UnexpectedValueException;

/**
 * Decorator class to wrap an element without already knowing the specific underlying type.
 *
 * Provides accessor methods to test the underlying type and return a type hinted instance of the concrete element.
 */
class UnspecifiedType implements ElementBase
{
    public function __construct(
        /**
         * The wrapped element.
         */
        private readonly Element $_element
    ) {
    }

    /**
     * Initialize from DER data.
     *
     * @param string $data DER encoded data
     */
    public static function fromDER(string $data): self
    {
        return Element::fromDER($data)->asUnspecified();
    }

    /**
     * Initialize from `ElementBase` interface.
     */
    public static function fromElementBase(ElementBase $el): self
    {
        // if element is already wrapped
        if ($el instanceof self) {
            return $el;
        }
        return new self($el->asElement());
    }

    /**
     * Get the wrapped element as a context specific tagged type.
     */
    public function asTagged(): TaggedType
    {
        if (! $this->_element instanceof TaggedType) {
            throw new UnexpectedValueException('Tagged element expected, got ' . $this->_typeDescriptorString());
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an application specific type.
     */
    public function asApplication(): ApplicationType
    {
        if (! $this->_element instanceof ApplicationType) {
            throw new UnexpectedValueException('Application type expected, got ' . $this->_typeDescriptorString());
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a private tagged type.
     */
    public function asPrivate(): PrivateType
    {
        if (! $this->_element instanceof PrivateType) {
            throw new UnexpectedValueException('Private type expected, got ' . $this->_typeDescriptorString());
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a boolean type.
     */
    public function asBoolean(): Boolean
    {
        if (! $this->_element instanceof Boolean) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_BOOLEAN));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an integer type.
     */
    public function asInteger(): Integer
    {
        if (! $this->_element instanceof Integer) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_INTEGER));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a bit string type.
     */
    public function asBitString(): BitString
    {
        if (! $this->_element instanceof BitString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_BIT_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an octet string type.
     */
    public function asOctetString(): OctetString
    {
        if (! $this->_element instanceof OctetString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_OCTET_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a null type.
     */
    public function asNull(): NullType
    {
        if (! $this->_element instanceof NullType) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_NULL));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an object identifier type.
     */
    public function asObjectIdentifier(): ObjectIdentifier
    {
        if (! $this->_element instanceof ObjectIdentifier) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_OBJECT_IDENTIFIER));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an object descriptor type.
     */
    public function asObjectDescriptor(): ObjectDescriptor
    {
        if (! $this->_element instanceof ObjectDescriptor) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_OBJECT_DESCRIPTOR));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a real type.
     */
    public function asReal(): Real
    {
        if (! $this->_element instanceof Real) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_REAL));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an enumerated type.
     */
    public function asEnumerated(): Enumerated
    {
        if (! $this->_element instanceof Enumerated) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_ENUMERATED));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a UTF8 string type.
     */
    public function asUTF8String(): UTF8String
    {
        if (! $this->_element instanceof UTF8String) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_UTF8_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a relative OID type.
     */
    public function asRelativeOID(): RelativeOID
    {
        if (! $this->_element instanceof RelativeOID) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_RELATIVE_OID));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a sequence type.
     */
    public function asSequence(): Sequence
    {
        if (! $this->_element instanceof Sequence) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_SEQUENCE));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a set type.
     */
    public function asSet(): Set
    {
        if (! $this->_element instanceof Set) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_SET));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a numeric string type.
     */
    public function asNumericString(): NumericString
    {
        if (! $this->_element instanceof NumericString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_NUMERIC_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a printable string type.
     */
    public function asPrintableString(): PrintableString
    {
        if (! $this->_element instanceof PrintableString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_PRINTABLE_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a T61 string type.
     */
    public function asT61String(): T61String
    {
        if (! $this->_element instanceof T61String) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_T61_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a videotex string type.
     */
    public function asVideotexString(): VideotexString
    {
        if (! $this->_element instanceof VideotexString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_VIDEOTEX_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a IA5 string type.
     */
    public function asIA5String(): IA5String
    {
        if (! $this->_element instanceof IA5String) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_IA5_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as an UTC time type.
     */
    public function asUTCTime(): UTCTime
    {
        if (! $this->_element instanceof UTCTime) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_UTC_TIME));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a generalized time type.
     */
    public function asGeneralizedTime(): GeneralizedTime
    {
        if (! $this->_element instanceof GeneralizedTime) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_GENERALIZED_TIME));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a graphic string type.
     */
    public function asGraphicString(): GraphicString
    {
        if (! $this->_element instanceof GraphicString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_GRAPHIC_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a visible string type.
     */
    public function asVisibleString(): VisibleString
    {
        if (! $this->_element instanceof VisibleString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_VISIBLE_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a general string type.
     */
    public function asGeneralString(): GeneralString
    {
        if (! $this->_element instanceof GeneralString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_GENERAL_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a universal string type.
     */
    public function asUniversalString(): UniversalString
    {
        if (! $this->_element instanceof UniversalString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_UNIVERSAL_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a character string type.
     */
    public function asCharacterString(): CharacterString
    {
        if (! $this->_element instanceof CharacterString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_CHARACTER_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a BMP string type.
     */
    public function asBMPString(): BMPString
    {
        if (! $this->_element instanceof BMPString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_BMP_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as a constructed string type.
     */
    public function asConstructedString(): ConstructedString
    {
        if (! $this->_element instanceof ConstructedString) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_CONSTRUCTED_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as any string type.
     */
    public function asString(): StringType
    {
        if (! $this->_element instanceof StringType) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_STRING));
        }
        return $this->_element;
    }

    /**
     * Get the wrapped element as any time type.
     */
    public function asTime(): TimeType
    {
        if (! $this->_element instanceof TimeType) {
            throw new UnexpectedValueException($this->_generateExceptionMessage(Element::TYPE_TIME));
        }
        return $this->_element;
    }

    public function asElement(): Element
    {
        return $this->_element;
    }

    public function asUnspecified(): UnspecifiedType
    {
        return $this;
    }

    public function toDER(): string
    {
        return $this->_element->toDER();
    }

    public function typeClass(): int
    {
        return $this->_element->typeClass();
    }

    public function tag(): int
    {
        return $this->_element->tag();
    }

    public function isConstructed(): bool
    {
        return $this->_element->isConstructed();
    }

    public function isType(int $tag): bool
    {
        return $this->_element->isType($tag);
    }

    public function isTagged(): bool
    {
        return $this->_element->isTagged();
    }

    /**
     * {@inheritdoc}
     *
     * Consider using any of the `as*` accessor methods instead.
     */
    public function expectType(int $tag): ElementBase
    {
        return $this->_element->expectType($tag);
    }

    /**
     * {@inheritdoc}
     *
     * Consider using `asTagged()` method instead and chaining
     * with `TaggedType::asExplicit()` or `TaggedType::asImplicit()`.
     */
    public function expectTagged(?int $tag = null): TaggedType
    {
        return $this->_element->expectTagged($tag);
    }

    /**
     * Generate message for exceptions thrown by `as*` methods.
     *
     * @param int $tag Type tag of the expected element
     */
    private function _generateExceptionMessage(int $tag): string
    {
        return sprintf('%s expected, got %s.', Element::tagToName($tag), $this->_typeDescriptorString());
    }

    /**
     * Get textual description of the wrapped element for debugging purposes.
     */
    private function _typeDescriptorString(): string
    {
        $type_cls = $this->_element->typeClass();
        $tag = $this->_element->tag();
        $str = $this->_element->isConstructed() ? 'constructed ' : 'primitive ';
        if (Identifier::CLASS_UNIVERSAL === $type_cls) {
            $str .= Element::tagToName($tag);
        } else {
            $str .= Identifier::classToName($type_cls) . " TAG {$tag}";
        }
        return $str;
    }
}
