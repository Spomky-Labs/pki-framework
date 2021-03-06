<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\MapStep;

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
        static::assertEquals($expected, $step->apply($string));
    }

    public function provideApplyCaseFold(): iterable
    {
        yield ['abc', 'abc'];
        yield ['ABC', 'abc'];
    }
}
