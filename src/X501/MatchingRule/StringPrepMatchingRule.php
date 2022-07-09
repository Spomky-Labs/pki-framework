<?php

declare(strict_types=1);

namespace Sop\X501\MatchingRule;

use Sop\X501\StringPrep\StringPreparer;

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

    public function compare($assertion, $value): ?bool
    {
        $assertion = $this->_prep->prepare($assertion);
        $value = $this->_prep->prepare($value);
        return 0 === strcmp($assertion, $value);
    }
}
