<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use Sop\X501\StringPrep\ProhibitStep;

/**
 * @internal
 */
final class ProhibitStepTest extends TestCase
{
    /**
     * @test
     */
    public function apply()
    {
        $str = 'Test';
        $step = new ProhibitStep();
        static::assertEquals($str, $step->apply($str));
    }
}
