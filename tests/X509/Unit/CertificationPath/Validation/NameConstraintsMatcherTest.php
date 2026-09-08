<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath\Validation;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\NameConstraintsMatcher;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\IPv4Address;
use SpomkyLabs\Pki\X509\GeneralName\IPv6Address;
use SpomkyLabs\Pki\X509\GeneralName\RegisteredID;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class NameConstraintsMatcherTest extends TestCase
{
    public static function dnsNames(): iterable
    {
        yield ['example.com', 'example.com', true];
        yield ['example.com', 'www.example.com', true];
        yield ['example.com', 'a.b.example.com', true];
        yield ['example.com', 'EXAMPLE.COM', true];
        yield ['EXAMPLE.COM', 'www.example.com', true];
        yield ['example.com', 'notexample.com', false];
        yield ['example.com', 'example.com.evil.tld', false];
        yield ['example.com', 'evil.tld', false];
        yield ['.example.com', 'www.example.com', true];
        yield ['.example.com', 'example.com', false];
        yield ['', 'anything.tld', true];
    }

    #[Test]
    #[DataProvider('dnsNames')]
    public function dnsName(string $base, string $name, bool $expected): void
    {
        $subtree = GeneralSubtree::create(DNSName::create($base));
        static::assertSame($expected, NameConstraintsMatcher::matches($subtree, DNSName::create($name)));
    }

    public static function emailAddresses(): iterable
    {
        yield ['example.com', 'bob@example.com', true];
        yield ['example.com', 'bob@EXAMPLE.COM', true];
        yield ['example.com', 'bob@sales.example.com', false];
        yield ['.example.com', 'bob@sales.example.com', true];
        yield ['.example.com', 'bob@example.com', false];
        yield ['bob@example.com', 'bob@example.com', true];
        yield ['bob@example.com', 'bob@EXAMPLE.COM', true];
        yield ['bob@example.com', 'BOB@example.com', false];
        yield ['bob@example.com', 'alice@example.com', false];
        yield ['example.com', 'not-an-address', false];
        yield ['', 'bob@example.com', true];
    }

    #[Test]
    #[DataProvider('emailAddresses')]
    public function email(string $base, string $name, bool $expected): void
    {
        $subtree = GeneralSubtree::create(RFC822Name::create($base));
        static::assertSame($expected, NameConstraintsMatcher::matches($subtree, RFC822Name::create($name)));
    }

    public static function uris(): iterable
    {
        yield ['example.com', 'http://example.com/path', true];
        yield ['example.com', 'https://EXAMPLE.COM', true];
        yield ['example.com', 'http://www.example.com/', false];
        yield ['.example.com', 'http://www.example.com/', true];
        yield ['.example.com', 'http://example.com/', false];
        yield ['example.com', 'http://evil.tld/', false];
        yield ['', 'http://example.com/', true];
    }

    #[Test]
    #[DataProvider('uris')]
    public function uri(string $base, string $name, bool $expected): void
    {
        $subtree = GeneralSubtree::create(UniformResourceIdentifier::create($base));
        static::assertSame(
            $expected,
            NameConstraintsMatcher::matches($subtree, UniformResourceIdentifier::create($name))
        );
    }

    #[Test]
    public function uriWithoutHostIsRejected(): void
    {
        $subtree = GeneralSubtree::create(UniformResourceIdentifier::create('example.com'));
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('cannot be matched against a name constraint');
        NameConstraintsMatcher::matches($subtree, UniformResourceIdentifier::create('urn:example:resource'));
    }

    public static function directoryNames(): iterable
    {
        yield ['c=FI', 'cn=EE,c=FI', true];
        yield ['c=FI', 'c=FI', true];
        yield ['c=FI', 'cn=EE,c=SE', false];
        yield ['cn=EE,c=FI', 'c=FI', false];
        yield ['o=ACME,c=FI', 'cn=EE,o=ACME,c=FI', true];
        yield ['o=ACME,c=FI', 'cn=EE,o=Other,c=FI', false];
    }

    #[Test]
    #[DataProvider('directoryNames')]
    public function directoryName(string $base, string $name, bool $expected): void
    {
        $subtree = GeneralSubtree::create(DirectoryName::fromDNString($base));
        static::assertSame(
            $expected,
            NameConstraintsMatcher::matches($subtree, DirectoryName::fromDNString($name))
        );
    }

    public static function ipv4Addresses(): iterable
    {
        yield ['192.168.0.0', '255.255.0.0', '192.168.1.1', true];
        yield ['192.168.0.0', '255.255.0.0', '192.169.1.1', false];
        yield ['192.168.0.0', '255.255.255.255', '192.168.0.0', true];
        yield ['192.168.0.0', '0.0.0.0', '10.0.0.1', true];
    }

    #[Test]
    #[DataProvider('ipv4Addresses')]
    public function ipv4Address(string $base, string $mask, string $name, bool $expected): void
    {
        $subtree = GeneralSubtree::create(IPv4Address::create($base, $mask));
        static::assertSame($expected, NameConstraintsMatcher::matches($subtree, IPv4Address::create($name)));
    }

    #[Test]
    public function ipv4AddressWithoutMaskRequiresExactMatch(): void
    {
        $subtree = GeneralSubtree::create(IPv4Address::create('192.168.0.1'));
        static::assertTrue(NameConstraintsMatcher::matches($subtree, IPv4Address::create('192.168.0.1')));
        static::assertFalse(NameConstraintsMatcher::matches($subtree, IPv4Address::create('192.168.0.2')));
    }

    #[Test]
    public function ipv6Address(): void
    {
        $subtree = GeneralSubtree::create(
            IPv6Address::create('2001:0db8:0000:0000:0000:0000:0000:0000', 'ffff:ffff:0000:0000:0000:0000:0000:0000')
        );
        static::assertTrue(
            NameConstraintsMatcher::matches(
                $subtree,
                IPv6Address::create('2001:0db8:0000:0000:0000:0000:0000:0001')
            )
        );
        static::assertFalse(
            NameConstraintsMatcher::matches(
                $subtree,
                IPv6Address::create('2001:0db9:0000:0000:0000:0000:0000:0001')
            )
        );
    }

    #[Test]
    public function ipv4ConstraintDoesNotMatchIPv6Address(): void
    {
        $subtree = GeneralSubtree::create(IPv4Address::create('0.0.0.0', '0.0.0.0'));
        static::assertFalse(
            NameConstraintsMatcher::matches(
                $subtree,
                IPv6Address::create('2001:0db8:0000:0000:0000:0000:0000:0001')
            )
        );
    }

    #[Test]
    public function invalidIPAddressIsRejected(): void
    {
        // An address that is not an address is now refused where it is written, rather than travelling as far as
        // the matcher inside a name whose encoding would have meant something else.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Address is not a valid IPv4 address.');
        IPv4Address::create('not an ip');
    }

    #[Test]
    public function invalidMaskIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Mask is not a valid IPv4 address.');
        IPv4Address::create('192.168.0.0', 'not a mask');
    }

    #[Test]
    public function namesOfDifferentTypesNeverMatch(): void
    {
        $subtree = GeneralSubtree::create(DNSName::create('example.com'));
        static::assertFalse(NameConstraintsMatcher::matches($subtree, RFC822Name::create('bob@example.com')));
    }

    #[Test]
    public function unsupportedNameTypeIsRejected(): void
    {
        $subtree = GeneralSubtree::create(RegisteredID::create('1.3.6.1.3.1'));
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('type ' . GeneralName::TAG_REGISTERED_ID . ' is not supported');
        NameConstraintsMatcher::assertSupported($subtree);
    }

    #[Test]
    public function minimumIsRejected(): void
    {
        $subtree = GeneralSubtree::create(DNSName::create('example.com'), 1);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('minimum or maximum');
        NameConstraintsMatcher::assertSupported($subtree);
    }

    #[Test]
    public function maximumIsRejected(): void
    {
        $subtree = GeneralSubtree::create(DNSName::create('example.com'), 0, 2);
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('minimum or maximum');
        NameConstraintsMatcher::assertSupported($subtree);
    }

    #[Test]
    public function supportedSubtreeIsAccepted(): void
    {
        $subtree = GeneralSubtree::create(DNSName::create('example.com'));
        NameConstraintsMatcher::assertSupported($subtree);
        static::assertTrue(NameConstraintsMatcher::matches($subtree, DNSName::create('example.com')));
    }
}
