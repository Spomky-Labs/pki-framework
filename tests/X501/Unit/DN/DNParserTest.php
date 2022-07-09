<?php

declare(strict_types=1);

namespace Sop\Test\X501\Unit\DN;

use Iterator;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\X501\DN\DNParser;
use UnexpectedValueException;

/**
 * @group dn
 *
 * @internal
 */
class DNParserTest extends TestCase
{
    /**
     * @dataProvider provideParseString
     *
     * @param string $dn Distinguished name
     * @param array $expected Parser result
     */
    public function testParseString($dn, $expected)
    {
        $result = DNParser::parseString($dn);
        $this->assertEquals($expected, $result);
    }

    public function provideParseString(): Iterator
    {
        yield [
            // single attribute
            'cn=name',
            [[['cn', 'name']]],
        ];
        yield [
            // uppercase name
            'CN=name',
            [[['CN', 'name']]],
        ];
        yield [
            // uppercase value
            'C=FI',
            [[['C', 'FI']]],
        ];
        yield [
            // multiple name-components
            'cn=one,cn=two',
            [[['cn', 'two']], [['cn', 'one']]],
        ];
        yield [
            // multiple attributes in name-component
            'cn=one+cn=two',
            [[['cn', 'one'], ['cn', 'two']]],
        ];
        yield [
            // multiple name-components and attributes
            'cn=one+cn=two,cn=three+cn=four',
            [[['cn', 'three'], ['cn', 'four']],
                [['cn', 'one'], ['cn', 'two']], ],
        ];
        yield [
            // empty attribute value
            'cn=',
            [[['cn', '']]],
        ];
        yield [
            // ignorable whitespace between name-components
            'cn = one , cn = two',
            [[['cn', 'two']], [['cn', 'one']]],
        ];
        yield [
            // ignorable whitespace between attributes
            'cn = one + cn = two',
            [[['cn', 'one'], ['cn', 'two']]],
        ];
        yield [
            // escaped whitespace
            'cn=one\\ ,cn=\\ two',
            [[['cn', ' two']], [['cn', 'one ']]],
        ];
        yield [
            // escaped and ignorable whitespace
            'cn = one\\  , cn = \\ two',
            [[['cn', ' two']], [['cn', 'one ']]],
        ];
        yield [
            // empty value with whitespace
            'cn = ',
            [[['cn', '']]],
        ];
        yield [
            // OID
            '1.2.3.4=val',
            [[['1.2.3.4', 'val']]],
        ];
        yield [
            // OID with prefix
            'oid.1.2.3.4=val',
            [[['1.2.3.4', 'val']]],
        ];
        yield [
            // OID with uppercase prefix
            'OID.1.2.3.4=val',
            [[['1.2.3.4', 'val']]],
        ];
        yield [
            // special characters
            'cn=\,\=\+\<\>\#\;\\\\\"',
            [[['cn', ',=+<>#;\\"']]],
        ];
        yield [
            // space inside attribute value
            'cn=one two',
            [[['cn', 'one two']]],
        ];
        yield [
            // consecutive spaces inside attribute value
            'cn=one   two',
            [[['cn', 'one   two']]],
        ];
        yield [
            // quotation
            'cn="value"',
            [[['cn', 'value']]],
        ];
        yield [
            // quote many
            'cn="one",cn="two"',
            [[['cn', 'two']], [['cn', 'one']]],
        ];
        yield [
            // quoted special characters
            'cn=",=+<>#;\\\\\""',
            [[['cn', ',=+<>#;\\"']]],
        ];
        yield [
            // quoted whitespace
            'cn="   "',
            [[['cn', '   ']]],
        ];
        yield [
            // hexpair
            'cn=\\20',
            [[['cn', ' ']]],
        ];
        yield [
            // hexstring
            'cn=#0101ff',
            [[['cn', new Boolean(true)]]],
        ];
        yield [
            // semicolon separator
            'cn=one;cn=two',
            [[['cn', 'two']], [['cn', 'one']]],
        ];
    }

    /**
     * @dataProvider provideEscapeString
     *
     * @param string $str
     * @param string $expected
     */
    public function testEscapeString($str, $expected)
    {
        $escaped = DNParser::escapeString($str);
        $this->assertEquals($expected, $escaped);
    }

    public function provideEscapeString(): Iterator
    {
        yield [',', '\,'];
        yield ['+', '\+'];
        yield ['"', '\"'];
        yield ['\\', '\\\\'];
        yield ['<', '\<'];
        yield ['>', '\>'];
        yield [';', '\;'];
        yield ['test ', 'test\ '];
        yield ['test  ', 'test \ '];
        yield [' test', '\ test'];
        yield ['  test', '\  test'];
        yield ["\x00", '\00'];
        // UTF-8 'ZERO WIDTH SPACE'
        yield ["\xE2\x80\x8B", '\E2\80\8B'];
    }

    public function testUnexpectedNameEnd()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Parser finished before the end of string');
        DNParser::parseString('cn=#05000');
    }

    public function testInvalidTypeAndValuePair()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid type and value pair');
        DNParser::parseString('cn');
    }

    public function testInvalidAttributeType()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid attribute type');
        DNParser::parseString('#00=fail');
    }

    public function testUnexpectedQuotation()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Unexpected quotation');
        DNParser::parseString('cn=fa"il');
    }

    public function testInvalidHexString()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid hexstring');
        DNParser::parseString('cn=#.');
    }

    public function testInvalidHexDER()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid DER encoding from hexstring');
        DNParser::parseString('cn=#badcafee');
    }

    public function testUnexpectedPairEnd()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Unexpected end of escape sequence');
        DNParser::parseString('cn=\\');
    }

    public function testUnexpectedHexPairEnd()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Unexpected end of hexpair');
        DNParser::parseString('cn=\\f');
    }

    public function testInvalidHexPair()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid hexpair');
        DNParser::parseString('cn=\\xx');
    }
}
