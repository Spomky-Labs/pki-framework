<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\StringPrep;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\StringPrep\MapStep;

/**
 * @internal
 */
final class MapStepTest extends TestCase
{
    #[Test]
    #[DataProvider('provideApplyCaseFold')]
    public function applyCaseFold(string $string, string $expected): void
    {
        $step = MapStep::create(true);
        static::assertSame($expected, $step->apply($string));
    }

    public static function provideApplyCaseFold(): iterable
    {
        yield ['abc', 'abc'];
        yield ['ABC', 'abc'];
    }
}
