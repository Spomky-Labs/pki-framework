<?php

declare(strict_types=1);

namespace unit\string-prep;

use PHPUnit\Framework\TestCase;
use Sop\X501\StringPrep\MapStep;

/**
 * @group string-prep
 *
 * @internal
 */
class MapStepTest extends TestCase
{
    /**
     * @dataProvider provideApplyCaseFold
     *
     * @param string $string
     * @param string $expected
     */
    public function testApplyCaseFold($string, $expected)
    {
        $step = new MapStep(true);
        $this->assertEquals($expected, $step->apply($string));
    }

    public function provideApplyCaseFold()
    {
        return [
            ['abc', 'abc'],
            ['ABC', 'abc'],
        ];
    }
}
