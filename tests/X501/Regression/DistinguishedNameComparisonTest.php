<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X501\Regression;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BMPString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\PrintableString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UniversalString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\UTF8String;
use SpomkyLabs\Pki\X501\ASN1\AttributeType;
use SpomkyLabs\Pki\X501\ASN1\AttributeTypeAndValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\AttributeValue;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X501\ASN1\RDN;

/**
 * Three defects let an attacker choose whether two distinguished names compared equal, which decides whether a
 * subject falls inside a directoryName name constraint, whether an issuer matches the working issuer name, and
 * whether a certificate is self-issued.
 *
 * The matching rule, and with it the RFC 4518 transcode step, was taken from one side only and then applied to the
 * other side's raw octets, so the same name encoded as a BMPString and as a PrintableString never compared equal.
 * The Map step was a stub, so a soft hyphen or a zero width space produced a name that renders identically and
 * compares differently. And transcoding substituted a replacement character for anything it could not decode, so
 * two values that were not the same collapsed onto one prepared string, which forges Certificate::isSelfIssued()
 * and defeats pathLenConstraint.
 *
 * @internal
 */
final class DistinguishedNameComparisonTest extends TestCase
{
    private const ORGANISATION = '2.5.4.10';

    private const VALUE = 'Acme Bank';

    /**
     * @return iterable<string, array{Element, Element}>
     */
    public static function encodingsOfTheSameName(): iterable
    {
        yield 'printable and utf8' => [
            PrintableString::create(self::VALUE),
            UTF8String::create(self::VALUE),
        ];
        yield 'printable and bmp' => [
            PrintableString::create(self::VALUE),
            BMPString::create(mb_convert_encoding(self::VALUE, 'UCS-2BE', 'UTF-8')),
        ];
        yield 'utf8 and universal' => [
            UTF8String::create(self::VALUE),
            UniversalString::create(mb_convert_encoding(self::VALUE, 'UCS-4BE', 'UTF-8')),
        ];
        yield 'bmp and universal' => [
            BMPString::create(mb_convert_encoding(self::VALUE, 'UCS-2BE', 'UTF-8')),
            UniversalString::create(mb_convert_encoding(self::VALUE, 'UCS-4BE', 'UTF-8')),
        ];
    }

    #[Test]
    #[DataProvider('encodingsOfTheSameName')]
    public function theStringTypeDoesNotChangeTheName(Element $left, Element $right): void
    {
        static::assertTrue(self::dn($left)->equals(self::dn($right)));
        // and the comparison is symmetric, which it was not
        static::assertTrue(self::dn($right)->equals(self::dn($left)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invisibleCharacters(): iterable
    {
        yield 'soft hyphen' => [self::VALUE . "\u{00AD}"];
        yield 'combining grapheme joiner' => [self::VALUE . "\u{034F}"];
        yield 'zero width space' => ["Acme\u{200B} Bank"];
        yield 'zero width non joiner' => ["Acme\u{200C} Bank"];
        yield 'zero width joiner' => ["Acme\u{200D} Bank"];
        yield 'byte order mark' => [self::VALUE . "\u{FEFF}"];
        yield 'variation selector' => [self::VALUE . "\u{FE00}"];
        yield 'tab in place of the space' => ["Acme\tBank"];
        yield 'no-break space in place of the space' => ["Acme\u{00A0}Bank"];
    }

    #[Test]
    #[DataProvider('invisibleCharacters')]
    public function aNameThatRendersTheSameCompareTheSame(string $value): void
    {
        static::assertTrue(self::dn(UTF8String::create(self::VALUE))->equals(self::dn(UTF8String::create($value))));
    }

    #[Test]
    public function caseIsFoldedRatherThanLowerCased(): void
    {
        // RFC 4518 asks for the case folding of RFC 3454 appendix B.2
        static::assertTrue(
            self::dn(UTF8String::create('Strasse'))->equals(self::dn(UTF8String::create("Stra\u{00DF}e")))
        );
        static::assertTrue(
            self::dn(UTF8String::create('acme bank'))->equals(self::dn(UTF8String::create('ACME BANK')))
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function namesThatDiffer(): iterable
    {
        yield 'a different organisation' => [self::VALUE, 'Evil Corp'];
        yield 'a longer name' => [self::VALUE, self::VALUE . ' Holdings'];
        yield 'a substring' => [self::VALUE, 'Acme'];
    }

    #[Test]
    #[DataProvider('namesThatDiffer')]
    public function differentNamesStillDiffer(string $left, string $right): void
    {
        static::assertFalse(self::dn(UTF8String::create($left))->equals(self::dn(UTF8String::create($right))));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function undecodableValues(): iterable
    {
        yield 'a lone high surrogate in a BMPString' => [BMPString::class, "\xd8\x00"];
        yield 'a lone low surrogate in a BMPString' => [BMPString::class, "\xdc\x00"];
        yield 'a surrogate in a UniversalString' => [UniversalString::class, "\x00\x00\xd8\x00"];
        yield 'a unit beyond Unicode' => [UniversalString::class, "\x7f\xff\xff\xff"];
    }

    #[Test]
    #[DataProvider('undecodableValues')]
    public function octetsThatDenoteNoCharacterAreRefused(string $class, string $octets): void
    {
        $this->expectException(InvalidArgumentException::class);
        $class::create($octets);
    }

    private static function dn(Element $value): Name
    {
        return Name::create(RDN::create(AttributeTypeAndValue::create(
            AttributeType::create(self::ORGANISATION),
            AttributeValue::fromASN1ByOID(self::ORGANISATION, $value->asUnspecified())
        )));
    }
}
