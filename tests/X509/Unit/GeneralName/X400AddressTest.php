<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

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
    /**
     * @test
     */
    public function create(): X400Address
    {
        $name = X400Address::fromASN1(new ImplicitlyTaggedType(GeneralName::TAG_X400_ADDRESS, new Sequence()));
        static::assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(X400Address $name): string
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
    public function choiceTag(string $der): void
    {
        $el = TaggedType::fromDER($der);
        static::assertEquals(GeneralName::TAG_X400_ADDRESS, $el->tag());
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode(string $der): X400Address
    {
        $name = X400Address::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(X400Address::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(X400Address $ref, X400Address $new): void
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(X400Address $name): void
    {
        static::assertIsString($name->string());
    }
}
