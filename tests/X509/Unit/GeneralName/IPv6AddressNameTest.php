<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\IPAddress;
use SpomkyLabs\Pki\X509\GeneralName\IPv6Address;
use UnexpectedValueException;

/**
 * @internal
 */
final class IPv6AddressNameTest extends TestCase
{
    public const ADDR = '0000:0000:0000:0000:0000:0000:0000:0001';

    public const MASK = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000';

    #[Test]
    public function create(): IPv6Address
    {
        // @todo implement compressed form handling
        $ip = IPv6Address::create(self::ADDR);
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    #[Test]
    #[Depends('create')]
    public function encode(IPAddress $ip): string
    {
        $el = $ip->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function choiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        static::assertSame(GeneralName::TAG_IP_ADDRESS, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(IPAddress $ref, IPAddress $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function iPv6(IPAddress $ip)
    {
        static::assertSame(self::ADDR, $ip->address());
    }

    #[Test]
    public function createWithMask()
    {
        $ip = IPv6Address::create(self::ADDR, self::MASK);
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    #[Test]
    #[Depends('createWithMask')]
    public function encodeWithMask(IPAddress $ip)
    {
        $el = $ip->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encodeWithMask')]
    public function decodeWithMask($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    #[Test]
    #[Depends('createWithMask')]
    #[Depends('decodeWithMask')]
    public function recodedWithMask(IPAddress $ref, IPAddress $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithMask')]
    public function mask(IPAddress $ip)
    {
        static::assertSame(self::MASK, $ip->mask());
    }

    #[Test]
    public function invalidOctetLength()
    {
        $this->expectException(UnexpectedValueException::class);
        IPv6Address::fromOctets('');
    }
}
