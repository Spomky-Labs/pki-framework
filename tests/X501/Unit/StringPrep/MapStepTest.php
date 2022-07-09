<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use Sop\X501\StringPrep\MapStep;

/**
 * @internal
 */
final class MapStepTest extends TestCase
{
    /**
     * @dataProvider provideApplyCaseFold
     *
     * @param string $string
     * @param string $expected
     *
     * @test
     */
    public function applyCaseFold($string, $expected)
    {
        $step = new MapStep(true);
        $this->assertEquals($expected, $step->apply($string));
    }

    public function provideApplyCaseFold()
    {
        return [['abc', 'abc'], ['ABC', 'abc']];
    }
}
