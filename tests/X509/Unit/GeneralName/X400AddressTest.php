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
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\X400Address;

/**
 * @internal
 */
final class X400AddressTest extends TestCase
{
    #[Test]
    public function create(): X400Address
    {
        $name = X400Address::fromASN1(ImplicitlyTaggedType::create(GeneralName::TAG_X400_ADDRESS, Sequence::create()));
        static::assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(X400Address $name): string
    {
        $el = $name->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    #[Test]
    #[Depends('encode')]
    public function choiceTag(string $der): void
    {
        $el = TaggedType::fromDER($der);
        static::assertSame(GeneralName::TAG_X400_ADDRESS, $el->tag());
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $der): X400Address
    {
        $name = X400Address::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(X400Address $ref, X400Address $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(X400Address $name): void
    {
        static::assertIsString($name->string());
    }
}
