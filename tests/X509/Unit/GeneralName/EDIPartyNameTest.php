<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\EDIPartyName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;

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
        static::assertInstanceOf(EDIPartyName::class, $name);
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
        static::assertEquals(GeneralName::TAG_EDI_PARTY_NAME, $el->tag());
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
        static::assertInstanceOf(EDIPartyName::class, $name);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(EDIPartyName $name)
    {
        static::assertIsString($name->string());
    }
}
