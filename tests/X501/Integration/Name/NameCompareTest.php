<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Integration\Name;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\ASN1\Name;

/**
 * @internal
 */
final class NameCompareTest extends TestCase
{
    /**
     * @param string $dn1
     * @param string $dn2
     * @param bool $expected
     */
    #[Test]
    #[DataProvider('provideCompareNames')]
    public function compareNames($dn1, $dn2, $expected)
    {
        $n1 = Name::fromString($dn1);
        $n2 = Name::fromString($dn2);
        static::assertEquals($expected, $n1->equals($n2));
    }

    /**
     * @param string $dn1
     * @param string $dn2
     * @param bool $expected
     */
    #[Test]
    #[DataProvider('provideCompareNames')]
    public function toStringMethod($dn1, $dn2, $expected)
    {
        $n1 = Name::fromString($dn1);
        static::assertSame($dn1, $n1->toString());
        $n2 = Name::fromString($dn2);
        static::assertSame($dn2, $n2->toString());
    }

    public static function provideCompareNames(): Iterator
    {
        yield ['cn=test', 'cn=test', true];
        yield ['cn=test1', 'cn=test2', false];
        yield ['cn=test,givenName=derp', 'cn=test,givenName=derp', true];
        yield ['cn=test,givenName=derp', 'cn=test,givenName=herp', false];
        yield ['cn=test+cn=alias', 'cn=test+cn=alias', true];
        yield ['cn=test+cn=alias', 'cn=test+cn=aliaz', false];
        yield ['cn=test,givenName=derp', 'cn=test', false];
        yield ['cn=test+cn=derp', 'cn=test', false];
        yield ['1.3.6.1.3=#0101ff', '1.3.6.1.3=#0101ff', true];
        yield ['1.3.6.1.3=#0101ff', '1.3.6.1.3=#010100', false];
        yield ['c=FI', 'c=FI', true];
    }
}
