<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Unit\DN;

use Iterator;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Boolean;
use SpomkyLabs\Pki\X501\DN\DNParser;
use UnexpectedValueException;

/**
 * @internal
 */
final class DNParserTest extends TestCase
{
    /**
     * @dataProvider provideParseString
     *
     * @param string $dn Distinguished name
     * @param array $expected Parser result
     *
     * @test
     */
    public function parseString($dn, $expected)
    {
        $result = DNParser::parseString($dn);
        static::assertEquals($expected, $result);
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
            [[['cn', 'three'], ['cn', 'four']], [['cn', 'one'], ['cn', 'two']]],
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
     *
     * @test
     */
    public function escapeString($str, $expected)
    {
        $escaped = DNParser::escapeString($str);
        static::assertEquals($expected, $escaped);
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

    /**
     * @test
     */
    public function unexpectedNameEnd()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Parser finished before the end of string');
        DNParser::parseString('cn=#05000');
    }

    /**
     * @test
     */
    public function invalidTypeAndValuePair()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid type and value pair');
        DNParser::parseString('cn');
    }

    /**
     * @test
     */
    public function invalidAttributeType()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid attribute type');
        DNParser::parseString('#00=fail');
    }

    /**
     * @test
     */
    public function unexpectedQuotation()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unexpected quotation');
        DNParser::parseString('cn=fa"il');
    }

    /**
     * @test
     */
    public function invalidHexString()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid hexstring');
        DNParser::parseString('cn=#.');
    }

    /**
     * @test
     */
    public function invalidHexDER()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid DER encoding from hexstring');
        DNParser::parseString('cn=#badcafee');
    }

    /**
     * @test
     */
    public function unexpectedPairEnd()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unexpected end of escape sequence');
        DNParser::parseString('cn=\\');
    }

    /**
     * @test
     */
    public function unexpectedHexPairEnd()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Unexpected end of hexpair');
        DNParser::parseString('cn=\\f');
    }

    /**
     * @test
     */
    public function invalidHexPair()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid hexpair');
        DNParser::parseString('cn=\\xx');
    }
}
