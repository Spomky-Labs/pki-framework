<?php

declare(strict_types=1);

namespace unit\string-prep;

use PHPUnit\Framework\TestCase;
use Sop\X501\StringPrep\CheckBidiStep;

/**
 * @group string-prep
 *
 * @internal
 */
class CheckBidiStepTest extends TestCase
{
    public function testApply()
    {
        $str = 'Test';
        $step = new CheckBidiStep();
        $this->assertEquals($str, $step->apply($str));
    }
}
