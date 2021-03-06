<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\MatchingRule;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X501\MatchingRule\CaseIgnoreMatch;

/**
 * @internal
 */
final class CaseIgnoreMatchTest extends TestCase
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
        $rule = new CaseIgnoreMatch(Element::TYPE_UTF8_STRING);
        static::assertEquals($expected, $rule->compare($assertion, $value));
    }

    public function provideMatch(): iterable
    {
        yield ['abc', 'abc', true];
        yield ['ABC', 'abc', true];
        yield [' abc ', 'abc', true];
        yield ['abc', ' abc ', true];
        yield ['a b c', 'a  b  c', true];
        yield ['abc', 'abcd', false];
        yield ['', '', true];
        yield ['', ' ', true];
    }
}
