<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\NameConstraintsMatcher;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * The matcher compared these names as raw bytes and read a URI host with parse_url(), so a subordinate CA fenced off
 * with an excludedSubtrees could issue for exactly that namespace by spelling the name differently.
 *
 * A trailing dot anchors a name at the DNS root and denotes the same host. parse_url() follows neither RFC 3986 nor
 * the WHATWG URL standard that consumers implement: the standard ends the authority at a backslash for the special
 * schemes, while parse_url() runs past it and takes the host after the last "@". Percent-encoding in the host is
 * decoded by consumers and not by parse_url().
 *
 * The permitted direction failed closed, so only the exclusions were bypassable.
 *
 * @internal
 */
final class NameConstraintCanonicalisationTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function unmatchableDNSNames(): iterable
    {
        yield 'trailing dot' => ['bank.example.com.'];
        yield 'two trailing dots' => ['bank.example.com..'];
        yield 'empty label' => ['bank..example.com'];
        yield 'leading dot' => ['.bank.example.com'];
        yield 'leading space' => [' bank.example.com'];
        yield 'trailing space' => ['bank.example.com '];
        yield 'empty name' => [''];
    }

    #[Test]
    #[DataProvider('unmatchableDNSNames')]
    public function aDNSNameWithNoComparableSpellingIsRefused(string $name): void
    {
        $subtree = GeneralSubtree::create(DNSName::create('bank.example.com'));
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('is not a host name that can be matched against a name constraint');
        NameConstraintsMatcher::matches($subtree, DNSName::create($name));
    }

    #[Test]
    public function anRFC822NameHostWithATrailingDotIsRefused(): void
    {
        $subtree = GeneralSubtree::create(RFC822Name::create('example.com'));
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('is not a host name that can be matched against a name constraint');
        NameConstraintsMatcher::matches($subtree, RFC822Name::create('bob@example.com.'));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function uriHosts(): iterable
    {
        // WHATWG ends the authority at the backslash, so the host is evil.example.com and the exclusion applies.
        yield 'backslash ends the authority' => ['http://evil.example.com\\@good.tld/', true];
        yield 'the mirror image' => ['http://good.tld\\@evil.example.com/', false];
        yield 'userinfo is not the host' => ['http://good.tld@evil.example.com/', true];
        yield 'a port is not part of the host' => ['http://evil.example.com:8443/', true];
        yield 'case is folded' => ['http://EVIL.EXAMPLE.COM/', true];
        yield 'a query cannot smuggle a host' => ['http://good.tld/?@evil.example.com', false];
        yield 'a fragment cannot smuggle a host' => ['http://good.tld/#@evil.example.com', false];
    }

    #[Test]
    #[DataProvider('uriHosts')]
    public function theURIAuthorityIsReadTheWayConsumersReadIt(string $uri, bool $expected): void
    {
        $subtree = GeneralSubtree::create(UniformResourceIdentifier::create('evil.example.com'));
        static::assertSame($expected, NameConstraintsMatcher::matches(
            $subtree,
            UniformResourceIdentifier::create($uri)
        ));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unmatchableURIs(): iterable
    {
        yield 'percent encoded host' => ['http://evil.ex%61mple.com/'];
        yield 'trailing dot on the host' => ['http://evil.example.com./'];
        yield 'no authority at all' => ['mailto:bob@evil.example.com'];
        yield 'empty authority' => ['http:///path'];
    }

    #[Test]
    #[DataProvider('unmatchableURIs')]
    public function aURIWithNoComparableHostIsRefused(string $uri): void
    {
        $subtree = GeneralSubtree::create(UniformResourceIdentifier::create('evil.example.com'));
        $this->expectException(PathValidationException::class);
        NameConstraintsMatcher::matches($subtree, UniformResourceIdentifier::create($uri));
    }

    /**
     * @return iterable<string, array{GeneralName, GeneralName, bool}>
     */
    public static function unchangedBehaviour(): iterable
    {
        yield 'the host itself' => [DNSName::create('example.com'), DNSName::create('example.com'), true];
        yield 'a host below it' => [DNSName::create('example.com'), DNSName::create('www.example.com'), true];
        yield 'the label boundary holds' => [
            DNSName::create('example.com'),
            DNSName::create('evilexample.com'),
            false,
        ];
        yield 'a suffix elsewhere' => [
            DNSName::create('example.com'),
            DNSName::create('example.com.evil.tld'),
            false,
        ];
        yield 'case is folded' => [DNSName::create('example.com'), DNSName::create('EXAMPLE.COM'), true];
        yield 'a wildcard label' => [DNSName::create('example.com'), DNSName::create('*.example.com'), true];
        yield 'an underscore label' => [DNSName::create('example.com'), DNSName::create('_acme.example.com'), true];
        yield 'a leading-dot constraint excludes the domain itself' => [
            DNSName::create('.example.com'),
            DNSName::create('example.com'),
            false,
        ];
        yield 'a leading-dot constraint takes subdomains' => [
            DNSName::create('.example.com'),
            DNSName::create('www.example.com'),
            true,
        ];
        yield 'a mailbox on the constrained host' => [
            RFC822Name::create('example.com'),
            RFC822Name::create('bob@example.com'),
            true,
        ];
        yield 'a mailbox one level down' => [
            RFC822Name::create('example.com'),
            RFC822Name::create('bob@sub.example.com'),
            false,
        ];
    }

    #[Test]
    #[DataProvider('unchangedBehaviour')]
    public function conformantNamesMatchAsBefore(GeneralName $base, GeneralName $name, bool $expected): void
    {
        static::assertSame($expected, NameConstraintsMatcher::matches(GeneralSubtree::create($base), $name));
    }
}
