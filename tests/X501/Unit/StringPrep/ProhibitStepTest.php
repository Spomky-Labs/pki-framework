<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\ProhibitStep;

/**
 * @internal
 */
final class ProhibitStepTest extends TestCase
{
    #[Test]
    public function apply()
    {
        $str = 'Test';
        $step = new ProhibitStep();
        static::assertSame($str, $step->apply($str));
    }
}
