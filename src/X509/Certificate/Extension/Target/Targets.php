<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension\Target;

use ArrayIterator;
use function count;
use Countable;
use IteratorAggregate;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * Implements *Targets* ASN.1 type as a *SEQUENCE OF Target*.
 *
 * @see https://tools.ietf.org/html/rfc5755#section-4.3.2
 */
final class Targets implements Countable, IteratorAggregate
{
    /**
     * Target elements.
     *
     * @var Target[]
     */
    private readonly array $_targets;

    public function __construct(Target ...$targets)
    {
        $this->_targets = $targets;
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(Sequence $seq): self
    {
        $targets = array_map(static fn (UnspecifiedType $el) => Target::fromASN1($el->asTagged()), $seq->elements());
        return new self(...$targets);
    }

    /**
     * Get all targets.
     *
     * @return Target[]
     */
    public function all(): array
    {
        return $this->_targets;
    }

    /**
     * Get all name targets.
     *
     * @return Target[]
     */
    public function nameTargets(): array
    {
        return $this->_allOfType(Target::TYPE_NAME);
    }

    /**
     * Get all group targets.
     *
     * @return Target[]
     */
    public function groupTargets(): array
    {
        return $this->_allOfType(Target::TYPE_GROUP);
    }

    /**
     * Check whether given target is present.
     */
    public function hasTarget(Target $target): bool
    {
        foreach ($this->_allOfType($target->type()) as $t) {
            if ($target->equals($t)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate ASN.1 structure.
     */
    public function toASN1(): Sequence
    {
        $elements = array_map(static fn (Target $target) => $target->toASN1(), $this->_targets);
        return Sequence::create(...$elements);
    }

    /**
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_targets);
    }

    /**
     * Get iterator for targets.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->_targets);
    }

    /**
     * Get all targets of given type.
     *
     * @return Target[]
     */
    private function _allOfType(int $type): array
    {
        return array_values(array_filter($this->_targets, static fn (Target $target) => $target->type() === $type));
    }
}
