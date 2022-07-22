<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate\Extension;

use ArrayIterator;
use function count;
use Countable;
use IteratorAggregate;
use LogicException;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use UnexpectedValueException;

/**
 * Implements 'CRL Distribution Points' certificate extension.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.2.1.13
 */
class CRLDistributionPointsExtension extends Extension implements Countable, IteratorAggregate
{
    /**
     * Distribution points.
     *
     * @var DistributionPoint[]
     */
    protected array $_distributionPoints;

    public function __construct(bool $critical, DistributionPoint ...$distribution_points)
    {
        parent::__construct(self::OID_CRL_DISTRIBUTION_POINTS, $critical);
        $this->_distributionPoints = $distribution_points;
    }

    /**
     * Get distribution points.
     *
     * @return DistributionPoint[]
     */
    public function distributionPoints(): array
    {
        return $this->_distributionPoints;
    }

    /**
     * Get the number of distribution points.
     *
     * @see \Countable::count()
     */
    public function count(): int
    {
        return count($this->_distributionPoints);
    }

    /**
     * Get iterator for distribution points.
     *
     * @see \IteratorAggregate::getIterator()
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->_distributionPoints);
    }

    protected static function _fromDER(string $data, bool $critical): static
    {
        $dps = array_map(
            fn (UnspecifiedType $el) => DistributionPoint::fromASN1($el->asSequence()),
            UnspecifiedType::fromDER($data)->asSequence()->elements()
        );
        if (! count($dps)) {
            throw new UnexpectedValueException('CRLDistributionPoints must have at least one DistributionPoint.');
        }
        // late static bound, extended by Freshest CRL extension
        return new static($critical, ...$dps);
    }

    protected function _valueASN1(): Element
    {
        if (! count($this->_distributionPoints)) {
            throw new LogicException('No distribution points.');
        }
        $elements = array_map(fn (DistributionPoint $dp) => $dp->toASN1(), $this->_distributionPoints);
        return Sequence::create(...$elements);
    }
}
