<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\IPAddress;
use Sop\X509\GeneralName\IPv4Address;
use UnexpectedValueException;

/**
 * @internal
 */
final class IPv4AddressNameTest extends TestCase
{
    public const ADDR = '127.0.0.1';

    public const MASK = '255.255.255.0';

    /**
     * @test
     */
    public function create()
    {
        $ip = new IPv4Address(self::ADDR);
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
    public function address(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR, $ip->address());
    }

    /**
     * @test
     */
    public function createWithMask()
    {
        $ip = new IPv4Address(self::ADDR, self::MASK);
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
     * @depends createWithMask
     *
     * @test
     */
    public function string(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR . '/' . self::MASK, $ip->string());
    }

    /**
     * @test
     */
    public function invalidOctetLength()
    {
        $this->expectException(UnexpectedValueException::class);
        IPv4Address::fromOctets('');
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noMaskFails(IPAddress $ip)
    {
        $this->expectException(LogicException::class);
        $ip->mask();
    }
}
