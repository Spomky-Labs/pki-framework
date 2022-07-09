<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\X400Address;

/**
 * @internal
 */
final class X400AddressTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = X400Address::fromASN1(new ImplicitlyTaggedType(GeneralName::TAG_X400_ADDRESS, new Sequence()));
        $this->assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(X400Address $name)
    {
        $el = $name->toASN1();
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
        $this->assertEquals(GeneralName::TAG_X400_ADDRESS, $el->tag());
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
        $name = X400Address::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(X400Address $ref, X400Address $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(X400Address $name)
    {
        $this->assertIsString($name->string());
    }
}
