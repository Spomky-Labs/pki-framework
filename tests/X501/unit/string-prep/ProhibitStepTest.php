<?php

declare(strict_types=1);

namespace unit\string-prep;

use PHPUnit\Framework\TestCase;
use Sop\X501\StringPrep\ProhibitStep;

/**
 * @group string-prep
 *
 * @internal
 */
class ProhibitStepTest extends TestCase
{
    public function testApply()
    {
        $str = 'Test';
        $step = new ProhibitStep();
        $this->assertEquals($str, $step->apply($str));
    }
}
