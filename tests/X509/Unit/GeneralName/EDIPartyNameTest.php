<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): EDIPartyName
    {
        $name = EDIPartyName::fromASN1(
            ImplicitlyTaggedType::create(GeneralName::TAG_EDI_PARTY_NAME, Sequence::create())
        );
        static::assertInstanceOf(EDIPartyName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(EDIPartyName $name): string
    {
        $el = $name->toASN1();
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
        static::assertSame(GeneralName::TAG_EDI_PARTY_NAME, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $name = EDIPartyName::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(EDIPartyName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(EDIPartyName $ref, EDIPartyName $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(EDIPartyName $name)
    {
        static::assertIsString($name->string());
    }
}
