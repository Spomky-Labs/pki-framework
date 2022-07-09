<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy;

use ArrayIterator;
use function count;
use Countable;
use IteratorAggregate;
use LogicException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *PolicyInformation* ASN.1 type used by 'Certificate Policies' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
final class PolicyInformation implements Countable, IteratorAggregate
{
    /**
     * Wildcard policy.
     *
     * @var string
     */
    final public const OID_ANY_POLICY = '2.5.29.32.0';

    /**
     * Policy qualifiers.
     *
     * @var PolicyQualifierInfo[]
     */
    private array $_qualifiers;

    public function __construct(
    /**
     * Policy identifier.
     */
    protected string $_oid,
        PolicyQualifierInfo ...$qualifiers
    ) {
        $this->_qualifiers = [];
        foreach ($qualifiers as $qual) {
            $this->_qualifiers[$qual->oid()] = $qual;
        }
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $oid = $seq->at(0)
            ->asObjectIdentifier()
            ->oid();
        $qualifiers = [];
        if (count($seq) > 1) {
            $qualifiers = array_map(
                fn (UnspecifiedType $el) => PolicyQualifierInfo::fromASN1($el->asSequence()),
                $seq->at(1)
                    ->asSequence()
                    ->elements()
            );
        }
        return new self($oid, ...$qualifiers);
    }

    /**
     * Get policy identifier.
     */
    public function oid(): string
    {
        return $this->_oid;
    }

    /**
     * Check whether this policy is anyPolicy.
     */
    public function isAnyPolicy(): bool
    {
        return $this->_oid === self::OID_ANY_POLICY;
    }

    /**
     * Get policy qualifiers.
     *
     * @return PolicyQualifierInfo[]
     */
    public function qualifiers(): array
    {
        return array_values($this->_qualifiers);
    }

    /**
     * Check whether qualifier is present.
     */
    public function has(string $oid): bool
    {
        return isset($this->_qualifiers[$oid]);
    }

    /**
     * Get qualifier by OID.
     */
    public function get(string $oid): PolicyQualifierInfo
    {
        if (! $this->has($oid)) {
            throw new LogicException("No {$oid} qualifier.");
        }
        return $this->_qualifiers[$oid];
    }

    /**
     * Check whether CPS qualifier is present.
     */
    public function hasCPSQualifier(): bool
    {
        return $this->has(PolicyQualifierInfo::OID_CPS);
    }

    /**
     * Get CPS qualifier.
     */
    public function CPSQualifier(): CPSQualifier
    {
        if (! $this->hasCPSQualifier()) {
            throw new LogicException('CPS qualifier not set.');
        }
        return $this->get(PolicyQualifierInfo::OID_CPS);
    }

    /**
     * Check whether user notice qualifier is present.
     */
    public function hasUserNoticeQualifier(): bool
    {
        return $this->has(PolicyQualifierInfo::OID_UNOTICE);
    }

    /**
     * Get user notice qualifier.
     */
    public function userNoticeQualifier(): UserNoticeQualifier
    {
        if (! $this->hasUserNoticeQualifier()) {
            throw new LogicException('User notice qualifier not set.');
        }
        return $this->get(PolicyQualifierInfo::OID_UNOTICE);
    }

    /**
     * Get ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = [new ObjectIdentifier($this->_oid)];
        if (count($this->_qualifiers)) {
            $qualifiers = array_map(
                fn (PolicyQualifierInfo $pqi) => $pqi->toASN1(),
                array_values($this->_qualifiers)
            );
            $elements[] = new Sequence(...$qualifiers);
        }
        return new Sequence(...$elements);
    }

    /**
     * Get number of qualifiers.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_qualifiers);
    }

    /**
     * Get iterator for qualifiers.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->_qualifiers);
    }
}
