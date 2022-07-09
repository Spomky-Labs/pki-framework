<?php

declare(strict_types=1);

namespace unit\dn;

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

    public function provideEqual()
    {
        return [
            // binary equal
            ['cn=one', 'cn=one'],
            // case-insensitive
            ['cn=one', 'cn=ONE'],
            // insignificant whitespace
            ['cn=one', 'cn=\\ one\\ '],
            // repeated inner whitespace
            ['cn=o n e ', 'cn=\\ o  n  e\\ '],
            // no-break space
            ['cn=on e', "cn=on\xC2\xA0e"],
            // multiple attributes
            ['cn=one,cn=two', 'cn=one,cn=two'],
            ['cn=one,cn=two', 'cn=ONE,cn=TWO'],
            ['cn=o n e,cn=two', 'cn=\\ o  n  e\\  , cn=\\ two\\  '],
        ];
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

    public function provideUnequal()
    {
        return [
            // value mismatch
            ['cn=one', 'cn=two'],
            ['cn=one,cn=two', 'cn=one,cn=three'],
            // attribute mismatch
            ['cn=one', 'name=one'],
            ['cn=one,cn=two', 'cn=one,name=two'],
        ];
    }
}
