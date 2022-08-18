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
    public function compare(mixed $assertion, mixed $value): ?bool
    {
        return strcmp((string) $assertion, (string) $value) === 0;
    }
}
