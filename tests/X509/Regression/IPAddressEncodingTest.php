<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\IPv4Address;
use SpomkyLabs\Pki\X509\GeneralName\IPv6Address;

/**
 * An iPAddress used to be encoded by splitting the string on its separators and packing the parts, which is not a
 * conversion at all. A compressed IPv6 address yields as many parts as it has written groups, so it packed to eight
 * octets and was then decoded as an IPv4 address followed by a subnet mask: the constraint the certificate carried
 * was not the constraint the operator wrote, and an all-zero mask matches every IPv4 address.
 *
 * @internal
 */
final class IPAddressEncodingTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function compressedIPv6Addresses(): iterable
    {
        yield 'trailing compression' => ['2001:db8::'];
        yield 'trailing compression with a host part' => ['2001:db8::1'];
        yield 'leading compression' => ['::1'];
        yield 'unspecified address' => ['::'];
        yield 'compression in the middle' => ['2001:db8::8a2e:370:7334'];
    }

    #[Test]
    #[DataProvider('compressedIPv6Addresses')]
    public function aCompressedIPv6AddressEncodesToSixteenOctets(string $address): void
    {
        $name = IPv6Address::create($address);
        $der = $name->toASN1()
            ->toDER();
        $decoded = GeneralName::fromASN1(Element::fromDER($der)->asUnspecified()->asTagged());

        static::assertInstanceOf(IPv6Address::class, $decoded);
        static::assertFalse($decoded->hasMask());
        static::assertSame(inet_pton($address), inet_pton($decoded->address()));
    }

    #[Test]
    public function anIPv6AddressWithAMaskRoundTrips(): void
    {
        $name = IPv6Address::create('2001:db8::', 'ffff:ffff::');
        $decoded = GeneralName::fromASN1(
            Element::fromDER($name->toASN1()->toDER())->asUnspecified()->asTagged()
        );

        static::assertInstanceOf(IPv6Address::class, $decoded);
        static::assertTrue($decoded->hasMask());
        static::assertSame(inet_pton('2001:db8::'), inet_pton($decoded->address()));
        static::assertSame(inet_pton('ffff:ffff::'), inet_pton($decoded->mask()));
    }

    #[Test]
    public function anIPv4AddressRoundTrips(): void
    {
        $name = IPv4Address::create('10.0.0.0', '255.0.0.0');
        $decoded = GeneralName::fromASN1(
            Element::fromDER($name->toASN1()->toDER())->asUnspecified()->asTagged()
        );

        static::assertInstanceOf(IPv4Address::class, $decoded);
        static::assertSame('10.0.0.0', $decoded->address());
        static::assertSame('255.0.0.0', $decoded->mask());
    }

    /**
     * @return iterable<string, array{string, null|string, string}>
     */
    public static function rejectedAddresses(): iterable
    {
        yield 'a CIDR suffix is not a mask' => ['10.0.0.0/8', null, 'Address is not a valid IPv4 address.'];
        yield 'an octet out of range' => ['192.0.2.300', null, 'Address is not a valid IPv4 address.'];
        yield 'too few octets' => ['192.0.2', null, 'Address is not a valid IPv4 address.'];
        yield 'not an address at all' => ['not an ip', null, 'Address is not a valid IPv4 address.'];
        yield 'a mask that is not an address' => ['192.0.2.0', 'not a mask', 'Mask is not a valid IPv4 address.'];
        yield 'an IPv6 address in an IPv4 name' => ['2001:db8::', null, 'Address is not a valid IPv4 address.'];
    }

    #[Test]
    #[DataProvider('rejectedAddresses')]
    public function anAddressThatIsNotAnAddressIsRefused(string $ip, ?string $mask, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        IPv4Address::create($ip, $mask);
    }

    #[Test]
    public function anIPv4AddressIsRefusedInAnIPv6Name(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Address is not a valid IPv6 address.');
        IPv6Address::create('192.0.2.1');
    }
}
