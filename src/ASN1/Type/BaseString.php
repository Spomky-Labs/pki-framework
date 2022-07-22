<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\ASN1\Type;

use InvalidArgumentException;
use SpomkyLabs\Pki\ASN1\Element;
use Stringable;

/**
 * Base class for all string types.
 */
abstract class BaseString extends Element implements StringType, Stringable
{
    /**
     * String value.
     *
     * @var string
     */
    protected $_string;

    public function __construct(string $string)
    {
        if (! $this->_validateString($string)) {
            throw new InvalidArgumentException(sprintf('Not a valid %s string.', self::tagToName($this->typeTag)));
        }
        $this->_string = $string;
    }

    public function __toString(): string
    {
        return $this->string();
    }

    /**
     * Get the string value.
     */
    public function string(): string
    {
        return $this->_string;
    }

    /**
     * Check whether string is valid for the concrete type.
     */
    protected function _validateString(string $string): bool
    {
        // Override in derived classes
        return true;
    }
}
