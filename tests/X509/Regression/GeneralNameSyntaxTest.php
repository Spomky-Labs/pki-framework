<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\IA5String;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * IA5String legitimately spans 0x00 to 0x7f, so an embedded NUL is a valid IA5 character and the ASN.1 decoder
 * has no reason to refuse it. A dNSName is not an arbitrary string, though: "www.bank.example.org\0.attacker.tld"
 * is the historic NUL prefix attack.
 *
 * @internal
 */
final class GeneralNameSyntaxTest extends TestCase
{
    #[Test]
    public function nulByteInDnsNameIsRejected(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('dNSName must not contain control characters');
        DNSName::create("www.bank.example.org\x00.attacker.tld");
    }

    #[Test]
    public function nulByteIsRejectedWhenDecoding(): void
    {
        // The attack arrives inside a certificate, not through create().
        $el = ImplicitlyTaggedType::create(
            GeneralName::TAG_DNS_NAME,
            IA5String::create("www.bank.example.org\x00.attacker.tld")
        );

        $this->expectException(UnexpectedValueException::class);
        GeneralName::fromASN1($el);
    }

    /**
     * @return Iterator<string, array{string}>
     */
    public static function controlCharacterProvider(): Iterator
    {
        yield 'NUL' => ["a\x00b"];
        yield 'LF' => ["a\nb"];
        yield 'CR' => ["a\rb"];
        yield 'TAB' => ["a\tb"];
        yield 'DEL' => ["a\x7fb"];
        yield 'leading NUL' => ["\x00example.com"];
        yield 'trailing NUL' => ["example.com\x00"];
    }

    #[Test]
    #[DataProvider('controlCharacterProvider')]
    public function controlCharactersAreRejectedInEveryTextualName(string $value): void
    {
        $rejected = 0;
        foreach ([DNSName::class, RFC822Name::class, UniformResourceIdentifier::class] as $class) {
            try {
                $class::create($value);
            } catch (UnexpectedValueException) {
                ++$rejected;
            }
        }
        static::assertSame(3, $rejected);
    }

    #[Test]
    public function overlongDnsNameIsRejected(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('at most 255 octets');
        DNSName::create(str_repeat('a', 256));
    }

    #[Test]
    public function ordinaryNamesAreStillAccepted(): void
    {
        // Deliberately lenient: names already in circulation use underscores and wildcards, and rejecting them
        // here would break certificates that validate everywhere else.
        foreach ([
            'example.com',
            '*.example.com',
            'xn--bcher-kva.example',
            'host_name.internal',
            str_repeat('a', 255),
        ] as $name) {
            static::assertSame($name, DNSName::create($name)->name());
        }

        static::assertSame('user@example.com', RFC822Name::create('user@example.com')->email());
        static::assertSame(
            'http://example.com/a?b=c#d',
            UniformResourceIdentifier::create('http://example.com/a?b=c#d')->uri()
        );
    }
}
