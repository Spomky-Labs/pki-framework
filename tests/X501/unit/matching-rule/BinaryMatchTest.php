<?php

declare(strict_types=1);

namespace unit\matching-rule;

use PHPUnit\Framework\TestCase;
use Sop\X501\MatchingRule\BinaryMatch;

/**
 * @group matching-rule
 *
 * @internal
 */
class BinaryMatchTest extends TestCase
{
    /**
     * @dataProvider provideMatch
     *
     * @param string $assertion
     * @param string $value
     * @param bool $expected
     */
    public function testMatch($assertion, $value, $expected)
    {
        $rule = new BinaryMatch();
        $this->assertEquals($expected, $rule->compare($assertion, $value));
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
