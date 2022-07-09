<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\MatchingRule;

use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\BinaryMatch;

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

    public function provideMatch()
    {
        return [
            ['abc', 'abc', true],
            ['ABC', 'abc', false],
            [' abc ', 'abc', false],
            ['abc', ' abc ', false],
            ['a b c', 'a  b  c', false],
            ['abc', 'abcd', false],
            ['', '', true],
            ['', ' ', false],
        ];
    }
}
