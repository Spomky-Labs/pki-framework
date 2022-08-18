<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\X501\MatchingRule;

use SpomkyLabs\Pki\X501\StringPrep\StringPreparer;

/**
 * Base class for matching rules employing string preparement semantics.
 */
abstract class StringPrepMatchingRule extends MatchingRule
{
    public function __construct(
        /**
         * String preparer.
         */
        protected StringPreparer $_prep
    ) {
    }

    public function compare(mixed $assertion, mixed $value): ?bool
    {
        $assertion = $this->_prep->prepare($assertion);
        $value = $this->_prep->prepare($value);
        return strcmp($assertion, $value) === 0;
    }
}
