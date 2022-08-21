<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X509\Certificate;

use DateTimeImmutable;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\GeneralizedTime;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTCTime;
use SpomkyLabs\Pki\ASN1\Type\TimeType;
use SpomkyLabs\Pki\X509\Feature\DateTimeHelper;
use UnexpectedValueException;

/**
 * Implements *Time* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-4.1
 */
final class Time
{
    use DateTimeHelper;

    /**
     * Time ASN.1 type tag.
     */
    protected int $_type;

    public function __construct(/**
     * Datetime.
     */
        protected DateTimeImmutable $_dt
    ) {
        $this->_type = self::_determineType($_dt);
    }

    /**
     * Initialize from ASN.1.
     */
    public static function fromASN1(TimeType $el): self
    {
        $obj = new self($el->dateTime());
        $obj->_type = $el->tag();
        return $obj;
    }

    /**
     * Initialize from date string.
     */
    public static function fromString(?string $time, ?string $tz = null): self
    {
        return new self(self::createDateTime($time, $tz));
    }

    public function dateTime(): DateTimeImmutable
    {
        return $this->_dt;
    }

    /**
     * Generate ASN.1.
     */
    public function toASN1(): TimeType
    {
        $dt = $this->_dt;
        switch ($this->_type) {
            case Element::TYPE_UTC_TIME:
                return UTCTime::create($dt);
            case Element::TYPE_GENERALIZED_TIME:
                // GeneralizedTime must not contain fractional seconds
                // (rfc5280 4.1.2.5.2)
                if ((int) $dt->format('u') !== 0) {
                    // remove fractional seconds (round down)
                    $dt = self::roundDownFractionalSeconds($dt);
                }
                return GeneralizedTime::create($dt);
        }
        throw new UnexpectedValueException('Time type ' . Element::tagToName($this->_type) . ' not supported.');
    }

    /**
     * Determine whether to use UTCTime or GeneralizedTime ASN.1 type.
     *
     * @return int Type tag
     */
    protected static function _determineType(DateTimeImmutable $dt): int
    {
        if ($dt->format('Y') >= 2050) {
            return Element::TYPE_GENERALIZED_TIME;
        }
        return Element::TYPE_UTC_TIME;
    }
}
