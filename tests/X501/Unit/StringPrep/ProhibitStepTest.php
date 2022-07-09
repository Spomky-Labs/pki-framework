<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\StringPrep;

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
