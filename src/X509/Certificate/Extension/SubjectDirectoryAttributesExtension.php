<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use ArrayIterator;
use function count;
use Countable;
use IteratorAggregate;
use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X501\ASN1\Attribute;
use SpomkyLabs\Pki\X501\ASN1\Collection\SequenceOfAttributes;
use UnexpectedValueException;

/**
 * Implements 'Subject Directory Attributes' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.8
 */
final class SubjectDirectoryAttributesExtension extends Extension implements Countable, IteratorAggregate
{
    /**
     * Attributes.
     */
    private readonly SequenceOfAttributes $_attributes;

    /**
     * @param Attribute ...$attribs One or more Attribute objects
     */
    public function __construct(bool $critical, Attribute ...$attribs)
    {
        parent::__construct(self::OID_SUBJECT_DIRECTORY_ATTRIBUTES, $critical);
        $this->_attributes = new SequenceOfAttributes(...$attribs);
    }

    /**
     * Check whether attribute is present.
     *
     * @param string $name OID or attribute name
     */
    public function has(string $name): bool
    {
        return $this->_attributes->has($name);
    }

    /**
     * Get first attribute by OID or attribute name.
     *
     * @param string $name OID or attribute name
     */
    public function firstOf(string $name): Attribute
    {
        return $this->_attributes->firstOf($name);
    }

    /**
     * Get all attributes of given name.
     *
     * @param string $name OID or attribute name
     *
     * @return Attribute[]
     */
    public function allOf(string $name): array
    {
        return $this->_attributes->allOf($name);
    }

    /**
     * Get all attributes.
     *
     * @return Attribute[]
     */
    public function all(): array
    {
        return $this->_attributes->all();
    }

    /**
     * Get number of attributes.
     */
    public function count(): int
    {
        return count($this->_attributes);
    }

    /**
     * Get iterator for attributes.
     *
     * @return ArrayIterator|Attribute[]
     */
    public function getIterator(): ArrayIterator
    {
        return $this->_attributes->getIterator();
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        $attribs = SequenceOfAttributes::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
        if (! count($attribs)) {
            throw new UnexpectedValueException('SubjectDirectoryAttributes must have at least one Attribute.');
        }
        return new self($critical, ...$attribs->all());
    }

    protected function _valueASN1(): Element
    {
        if (! count($this->_attributes)) {
            throw new LogicException('No attributes');
        }
        return $this->_attributes->toASN1();
    }
}
