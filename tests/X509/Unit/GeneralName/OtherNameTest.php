<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\OtherName;

/**
 * @internal
 */
final class OtherNameTest extends TestCase
{
    #[Test]
    public function create(): OtherName
    {
        $name = OtherName::create('1.3.6.1.3.1', NullType::create());
        static::assertInstanceOf(OtherName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(OtherName $name): string
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
        static::assertSame(GeneralName::TAG_OTHER_NAME, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $name = OtherName::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(OtherName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(OtherName $ref, OtherName $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(OtherName $name)
    {
        static::assertIsString($name->string());
    }

    #[Test]
    #[Depends('create')]
    public function oID(OtherName $name)
    {
        static::assertSame('1.3.6.1.3.1', $name->type());
    }

    #[Test]
    #[Depends('create')]
    public function value(OtherName $name)
    {
        static::assertEquals(NullType::create(), $name->value());
    }
}
