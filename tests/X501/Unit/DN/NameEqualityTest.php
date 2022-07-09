<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\DN;

use Iterator;
use PHPUnit\Framework\TestCase;
use Sop\X501\ASN1\Name;

/**
 * @group dn
 *
 * @internal
 */
class NameEqualityTest extends TestCase
{
    /**
     * @dataProvider provideEqual
     *
     * @param string $dn1
     * @param string $dn2
     */
    public function testEqual($dn1, $dn2)
    {
        $result = Name::fromString($dn1)->equals(Name::fromString($dn2));
        $this->assertTrue($result);
    }

    public function provideEqual(): Iterator
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
     * @dataProvider provideUnequal
     *
     * @param string $dn1
     * @param string $dn2
     */
    public function testUnequal($dn1, $dn2)
    {
        $result = Name::fromString($dn1)->equals(Name::fromString($dn2));
        $this->assertFalse($result);
    }

    public function provideUnequal(): Iterator
    {
        // value mismatch
        yield ['cn=one', 'cn=two'];
        yield ['cn=one,cn=two', 'cn=one,cn=three'];
        // attribute mismatch
        yield ['cn=one', 'name=one'];
        yield ['cn=one,cn=two', 'cn=one,name=two'];
    }
}
