<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use ArrayIterator;
use function count;
use Countable;
use IteratorAggregate;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\AccessDescription;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;

/**
 * Implements 'Subject Information Access' extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.2
 */
final class SubjectInformationAccessExtension extends Extension implements Countable, IteratorAggregate
{
    /**
     * Access descriptions.
     *
     * @var SubjectAccessDescription[]
     */
    private readonly array $_accessDescriptions;

    public function __construct(bool $critical, SubjectAccessDescription ...$access)
    {
        parent::__construct(self::OID_SUBJECT_INFORMATION_ACCESS, $critical);
        $this->_accessDescriptions = $access;
    }

    /**
     * Get the access descriptions.
     *
     * @return SubjectAccessDescription[]
     */
    public function accessDescriptions(): array
    {
        return $this->_accessDescriptions;
    }

    /**
     * Get the number of access descriptions.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_accessDescriptions);
    }

    /**
     * Get iterator for access descriptions.
     *
     * @see \IteratorAggregate::getIterator()
     *
     * @return ArrayIterator List of SubjectAccessDescription objects
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->_accessDescriptions);
    }

    protected static function _fromDER(string $data, bool $critical): Extension
    {
        $access = array_map(
            fn (UnspecifiedType $el) => SubjectAccessDescription::fromASN1($el->asSequence()),
            UnspecifiedType::fromDER($data)->asSequence()->elements()
        );
        return new self($critical, ...$access);
    }

    protected function _valueASN1(): Element
    {
        $elements = array_map(fn (AccessDescription $access) => $access->toASN1(), $this->_accessDescriptions);
        return new Sequence(...$elements);
    }
}
