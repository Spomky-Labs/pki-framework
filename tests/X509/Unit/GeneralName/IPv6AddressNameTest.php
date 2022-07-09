<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\IPAddress;
use Sop\X509\GeneralName\IPv6Address;
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
        $ip = new IPv6Address(self::ADDR);
        $this->assertInstanceOf(IPAddress::class, $ip);
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
        $this->assertInstanceOf(ImplicitTagging::class, $el);
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
        $this->assertEquals(GeneralName::TAG_IP_ADDRESS, $el->tag());
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
        $this->assertInstanceOf(IPAddress::class, $ip);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iPv6(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR, $ip->address());
    }

    /**
     * @test
     */
    public function createWithMask()
    {
        $ip = new IPv6Address(self::ADDR, self::MASK);
        $this->assertInstanceOf(IPAddress::class, $ip);
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
        $this->assertInstanceOf(ImplicitTagging::class, $el);
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
        $this->assertInstanceOf(IPAddress::class, $ip);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithMask
     *
     * @test
     */
    public function mask(IPAddress $ip)
    {
        $this->assertEquals(self::MASK, $ip->mask());
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
