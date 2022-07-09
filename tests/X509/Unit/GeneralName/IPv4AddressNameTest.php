<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\IPAddress;
use Sop\X509\GeneralName\IPv4Address;

/**
 * @group general-name
 *
 * @internal
 */
class IPv4AddressNameTest extends TestCase
{
    public const ADDR = '127.0.0.1';

    public const MASK = '255.255.255.0';

    public function testCreate()
    {
        $ip = new IPv4Address(self::ADDR);
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(IPAddress $ip)
    {
        $el = $ip->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testChoiceTag($der)
    {
        $el = TaggedType::fromDER($der);
        $this->assertEquals(GeneralName::TAG_IP_ADDRESS, $el->tag());
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(IPAddress $ref, IPAddress $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testAddress(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR, $ip->address());
    }

    public function testCreateWithMask()
    {
        $ip = new IPv4Address(self::ADDR, self::MASK);
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends testCreateWithMask
     */
    public function testEncodeWithMask(IPAddress $ip)
    {
        $el = $ip->toASN1();
        $this->assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @depends testEncodeWithMask
     *
     * @param string $der
     */
    public function testDecodeWithMask($der)
    {
        $ip = IPAddress::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(IPAddress::class, $ip);
        return $ip;
    }

    /**
     * @depends testCreateWithMask
     * @depends testDecodeWithMask
     */
    public function testRecodedWithMask(IPAddress $ref, IPAddress $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreateWithMask
     */
    public function testMask(IPAddress $ip)
    {
        $this->assertEquals(self::MASK, $ip->mask());
    }

    /**
     * @depends testCreateWithMask
     */
    public function testString(IPAddress $ip)
    {
        $this->assertEquals(self::ADDR . '/' . self::MASK, $ip->string());
    }

    public function testInvalidOctetLength()
    {
        $this->expectException(\UnexpectedValueException::class);
        IPv4Address::fromOctets('');
    }

    /**
     * @depends testCreate
     */
    public function testNoMaskFails(IPAddress $ip)
    {
        $this->expectException(\LogicException::class);
        $ip->mask();
    }
}
