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
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;

/**
 * Implements 'Authority Information Access' extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.2.1
 */
final class AuthorityInformationAccessExtension extends Extension implements Countable, IteratorAggregate
{
    /**
     * Access descriptions.
     *
     * @var AuthorityAccessDescription[]
     */
    private readonly array $_accessDescriptions;

    public function __construct(bool $critical, AuthorityAccessDescription ...$access)
    {
        parent::__construct(self::OID_AUTHORITY_INFORMATION_ACCESS, $critical);
        $this->_accessDescriptions = $access;
    }

    /**
     * Get the access descriptions.
     *
     * @return AuthorityAccessDescription[]
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
     * @return ArrayIterator List of AuthorityAccessDescription objects
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->_accessDescriptions);
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        $access = array_map(
            fn (UnspecifiedType $el) => AuthorityAccessDescription::fromASN1($el->asSequence()),
            UnspecifiedType::fromDER($data)->asSequence()->elements()
        );
        return new self($critical, ...$access);
    }

    protected function _valueASN1(): Element
    {
        $elements = array_map(fn (AccessDescription $access) => $access->toASN1(), $this->_accessDescriptions);
        return Sequence::create(...$elements);
    }
}
