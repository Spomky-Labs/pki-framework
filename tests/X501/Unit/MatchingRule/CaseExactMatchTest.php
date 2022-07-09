<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\MatchingRule;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\X501\MatchingRule\CaseExactMatch;

/**
 * @internal
 */
final class CaseExactMatchTest extends TestCase
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
        $rule = new CaseExactMatch(Element::TYPE_UTF8_STRING);
        static::assertEquals($expected, $rule->compare($assertion, $value));
    }

    public function provideMatch()
    {
        return [
            ['abc', 'abc', true],
            ['ABC', 'abc', false],
            [' abc ', 'abc', true],
            ['abc', ' abc ', true],
            ['a b c', 'a  b  c', true],
            ['abc', 'abcd', false],
            ['', '', true],
            ['', ' ', true],
        ];
    }
}
