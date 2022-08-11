<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type;

use DateTimeImmutable;
use SpomkyLabs\Pki\ASN1\Element;
use Stringable;

/**
 * Base class for all types representing a point in time.
 */
abstract class BaseTime extends Element implements TimeType, Stringable
{
    /**
     * UTC timezone.
     *
     * @var string
     */
    public const TZ_UTC = 'UTC';

    public function __construct(
        int $typeTag,
        protected readonly DateTimeImmutable $_dateTime
    ) {
        parent::__construct($typeTag);
    }

    public function __toString(): string
    {
        return $this->string();
    }

    /**
     * Initialize from datetime string.
     *
     * @see http://php.net/manual/en/datetime.formats.php
     *
     * @param string $time Time string
     */
    abstract public static function fromString(string $time): static;

    /**
     * Get the date and time.
     */
    public function dateTime(): DateTimeImmutable
    {
        return $this->_dateTime;
    }

    /**
     * Get the date and time as a type specific string.
     */
    public function string(): string
    {
        return $this->encodedAsDER();
    }

    /**
     * Get last error caused by `DateTimeImmutable`.
     */
    protected static function _getLastDateTimeImmutableErrorsStr(): string
    {
        $errors = DateTimeImmutable::getLastErrors()['errors'];
        return implode(', ', $errors);
    }
}
