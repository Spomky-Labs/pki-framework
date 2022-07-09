<?php

declare(strict_types=1);

namespace Sop\X501\StringPrep;

use const MB_CASE_LOWER;

/**
 * Implements 'Map' step of the Internationalized String Preparation as specified by RFC 4518.
 *
 * @see https://tools.ietf.org/html/rfc4518#section-2.2
 */
final class MapStep implements PrepareStep
{
    /**
     * Constructor.
     *
     * @param bool $_fold Whether to apply case folding
     */
    public function __construct(protected bool $_fold = false)
    {
    }

    /**
     * @param string $string UTF-8 encoded string
     */
    public function apply(string $string): string
    {
        // @todo Implement character mappings
        if ($this->_fold) {
            $string = mb_convert_case($string, MB_CASE_LOWER, 'UTF-8');
        }
        return $string;
    }
}
