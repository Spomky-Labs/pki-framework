<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

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

    /**
     * @test
     */
    public function create()
    {
        // @todo implement compressed form handling
        $ip = IPv6Address::create(self::ADDR);
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(IPAddress $ip)
    {
        $el = $ip->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function choiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        static::assertEquals(GeneralName::TAG_IP_ADDRESS, $el->tag());
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(IPAddress $ref, IPAddress $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iPv6(IPAddress $ip)
    {
        static::assertEquals(self::ADDR, $ip->address());
    }

    /**
     * @test
     */
    public function createWithMask()
    {
        $ip = IPv6Address::create(self::ADDR, self::MASK);
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends createWithMask
     *
     * @test
     */
    public function encodeWithMask(IPAddress $ip)
    {
        $el = $ip->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encodeWithMask
     *
     * @param string $der
     *
     * @test
     */
    public function decodeWithMask($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends createWithMask
     * @depends decodeWithMask
     *
     * @test
     */
    public function recodedWithMask(IPAddress $ref, IPAddress $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends createWithMask
     *
     * @test
     */
    public function mask(IPAddress $ip)
    {
        static::assertEquals(self::MASK, $ip->mask());
    }

    /**
     * @test
     */
    public function invalidOctetLength()
    {
        $this->expectException(UnexpectedValueException::class);
        IPv6Address::fromOctets('');
    }
}
