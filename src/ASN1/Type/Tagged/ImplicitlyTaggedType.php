<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type\Tagged;

use BadMethodCallException;
use SpomkyLabs\Pki\ASN1\Component\Identifier;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Feature\ElementBase;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use UnexpectedValueException;

/**
 * Implements implicit tagging mode.
 *
 * Implicit tagging changes the tag of the tagged type. This changes the DER encoding of the type, and hence the
 * abstract syntax must be known when decoding the data.
 */
class ImplicitlyTaggedType extends TaggedTypeWrap implements ImplicitTagging
{
    /**
     * @param int $tag Tag number
     * @param Element $element Wrapped element
     * @param int $class Type class
     */
    public function __construct(int $tag, Element $element, int $class = Identifier::CLASS_CONTEXT_SPECIFIC)
    {
        parent::__construct($element, $class);
        $this->typeTag = $tag;
    }

    public function isConstructed(): bool
    {
        // depends on the underlying type
        return $this->_element->isConstructed();
    }

    public function implicit(int $tag, int $class = Identifier::CLASS_UNIVERSAL): UnspecifiedType
    {
        $this->_element->expectType($tag);
        if ($this->_element->typeClass() !== $class) {
            throw new UnexpectedValueException(
                sprintf(
                    'Type class %s expected, got %s.',
                    Identifier::classToName($class),
                    Identifier::classToName($this->_element->typeClass())
                )
            );
        }
        return $this->_element->asUnspecified();
    }

    protected function encodedAsDER(): string
    {
        // get only the content of the wrapped element.
        return $this->_element->encodedAsDER();
    }

    protected static function decodeFromDER(Identifier $identifier, string $data, int &$offset): ElementBase
    {
        throw new BadMethodCallException(__METHOD__ . ' must be implemented in derived class.');
    }
}
