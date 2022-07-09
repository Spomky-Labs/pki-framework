<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\CheckBidiStep;

/**
 * @internal
 */
final class CheckBidiStepTest extends TestCase
{
    /**
     * @test
     */
    public function apply()
    {
        $str = 'Test';
        $step = new CheckBidiStep();
        static::assertEquals($str, $step->apply($str));
    }
}
