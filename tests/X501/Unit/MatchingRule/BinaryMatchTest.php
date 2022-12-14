<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\MatchingRule;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\MatchingRule\BinaryMatch;

/**
 * @internal
 */
final class BinaryMatchTest extends TestCase
{
    /**
     * @dataProvider provideMatch
     *
     * @param string $assertion
     * @param string $value
     * @param bool $expected
     *
     * @test
     */
    public function match($assertion, $value, $expected)
    {
        $rule = new BinaryMatch();
        static::assertEquals($expected, $rule->compare($assertion, $value));
    }

    public function provideMatch(): iterable
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
