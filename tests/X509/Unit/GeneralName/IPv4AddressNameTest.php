<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\IPAddress;
use SpomkyLabs\Pki\X509\GeneralName\IPv4Address;
use UnexpectedValueException;

/**
 * @internal
 */
final class IPv4AddressNameTest extends TestCase
{
    public const ADDR = '127.0.0.1';

    public const MASK = '255.255.255.0';

    #[Test]
    public function create(): IPv4Address
    {
        $ip = IPv4Address::create(self::ADDR);
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
    public function address(IPAddress $ip)
    {
        static::assertSame(self::ADDR, $ip->address());
    }

    #[Test]
    public function createWithMask()
    {
        $ip = IPv4Address::create(self::ADDR, self::MASK);
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
    #[Depends('createWithMask')]
    public function string(IPAddress $ip)
    {
        static::assertSame(self::ADDR . '/' . self::MASK, $ip->string());
    }

    #[Test]
    public function invalidOctetLength()
    {
        $this->expectException(UnexpectedValueException::class);
        IPv4Address::fromOctets('');
    }

    #[Test]
    #[Depends('create')]
    public function noMaskFails(IPAddress $ip)
    {
        $this->expectException(LogicException::class);
        $ip->mask();
    }
}
