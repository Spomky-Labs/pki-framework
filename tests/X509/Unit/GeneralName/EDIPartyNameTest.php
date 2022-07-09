<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\EDIPartyName;
use Sop\X509\GeneralName\GeneralName;

/**
 * @internal
 */
final class EDIPartyNameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = EDIPartyName::fromASN1(new ImplicitlyTaggedType(GeneralName::TAG_EDI_PARTY_NAME, new Sequence()));
        $this->assertInstanceOf(EDIPartyName::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(EDIPartyName $name)
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
        $this->assertEquals(GeneralName::TAG_EDI_PARTY_NAME, $el->tag());
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
        $name = EDIPartyName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(EDIPartyName::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(EDIPartyName $ref, EDIPartyName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(EDIPartyName $name)
    {
        $this->assertIsString($name->string());
    }
}
