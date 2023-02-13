<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\DN;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X501\ASN1\Name;

/**
 * @internal
 */
final class NameEqualityTest extends TestCase
{
    /**
     * @param string $dn1
     * @param string $dn2
     */
    #[Test]
    #[DataProvider('provideEqual')]
    public function equal($dn1, $dn2)
    {
        $result = Name::fromString($dn1)->equals(Name::fromString($dn2));
        static::assertTrue($result);
    }

    public static function provideEqual(): Iterator
    {
        // binary equal
        yield ['cn=one', 'cn=one'];
        // case-insensitive
        yield ['cn=one', 'cn=ONE'];
        // insignificant whitespace
        yield ['cn=one', 'cn=\\ one\\ '];
        // repeated inner whitespace
        yield ['cn=o n e ', 'cn=\\ o  n  e\\ '];
        // no-break space
        yield ['cn=on e', "cn=on\xC2\xA0e"];
        // multiple attributes
        yield ['cn=one,cn=two', 'cn=one,cn=two'];
        yield ['cn=one,cn=two', 'cn=ONE,cn=TWO'];
        yield ['cn=o n e,cn=two', 'cn=\\ o  n  e\\  , cn=\\ two\\  '];
    }

    /**
     * @param string $dn1
     * @param string $dn2
     */
    #[Test]
    #[DataProvider('provideUnequal')]
    public function unequal($dn1, $dn2)
    {
        $result = Name::fromString($dn1)->equals(Name::fromString($dn2));
        static::assertFalse($result);
    }

    public static function provideUnequal(): Iterator
    {
        // value mismatch
        yield ['cn=one', 'cn=two'];
        yield ['cn=one,cn=two', 'cn=one,cn=three'];
        // attribute mismatch
        yield ['cn=one', 'name=one'];
        yield ['cn=one,cn=two', 'cn=one,name=two'];
    }
}
