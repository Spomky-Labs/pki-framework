<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\DNSName;
use Sop\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class DNSNameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = new DNSName('test.example.com');
        static::assertInstanceOf(DNSName::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(DNSName $name)
    {
        $el = $name->toASN1();
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
        static::assertEquals(GeneralName::TAG_DNS_NAME, $el->tag());
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
        $name = DNSName::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(DNSName::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(DNSName $ref, DNSName $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function dNS(DNSName $name)
    {
        static::assertEquals('test.example.com', $name->name());
    }
}
