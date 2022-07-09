<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use Sop\X501\StringPrep\CheckBidiStep;

/**
 * @internal
 */
final class CheckBidiStepTest extends TestCase
{
    public function testApply()
    {
        $str = 'Test';
        $step = new CheckBidiStep();
        $this->assertEquals($str, $step->apply($str));
    }
}
