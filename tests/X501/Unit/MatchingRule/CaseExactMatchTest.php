<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\MatchingRule;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X501\MatchingRule\CaseExactMatch;

/**
 * @internal
 */
final class CaseExactMatchTest extends TestCase
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
        $rule = CaseExactMatch::create(Element::TYPE_UTF8_STRING);
        static::assertEquals($expected, $rule->compare($assertion, $value));
    }

    public static function provideMatch(): iterable
    {
        yield ['abc', 'abc', true];
        yield ['ABC', 'abc', false];
        yield [' abc ', 'abc', true];
        yield ['abc', ' abc ', true];
        yield ['a b c', 'a  b  c', true];
        yield ['abc', 'abcd', false];
        yield ['', '', true];
        yield ['', ' ', true];
    }
}
