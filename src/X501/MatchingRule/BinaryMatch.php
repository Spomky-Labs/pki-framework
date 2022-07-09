<?php

declare(strict_types=1);

namespace Sop\X501\MatchingRule;

/**
 * Implements binary matching rule.
 *
 * Generally used only by UnknownAttribute and custom attributes.
 */
final class BinaryMatch extends MatchingRule
{
    public function compare($assertion, $value): ?bool
    {
        return 0 === strcmp($assertion, $value);
    }
}
