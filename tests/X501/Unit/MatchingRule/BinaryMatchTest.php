<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\MatchingRule;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\MatchingRule\BinaryMatch;

/**
 * @internal
 */
final class BinaryMatchTest extends TestCase
{
    /**
     * @param string $assertion
     * @param string $value
     * @param bool $expected
     */
    #[Test]
    #[DataProvider('provideMatch')]
    public function match($assertion, $value, $expected)
    {
        $rule = new BinaryMatch();
        static::assertEquals($expected, $rule->compare($assertion, $value));
    }

    public static function provideMatch(): iterable
    {
        yield ['abc', 'abc', true];
        yield ['ABC', 'abc', false];
        yield [' abc ', 'abc', false];
        yield ['abc', ' abc ', false];
        yield ['a b c', 'a  b  c', false];
        yield ['abc', 'abcd', false];
        yield ['', '', true];
        yield ['', ' ', false];
    }
}
