<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\MatchingRule;

/**
 * Implements binary matching rule.
 *
 * Generally used only by UnknownAttribute and custom attributes.
 */
final class BinaryMatch extends MatchingRule
{
    public function compare($assertion, $value): ?bool
    {
        return strcmp($assertion, $value) === 0;
    }
}
