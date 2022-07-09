<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\ProhibitStep;

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
