<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;

/**
 * @internal
 */
final class RFC822NameTest extends TestCase
{
    #[Test]
    public function create(): RFC822Name
    {
        $name = RFC822Name::create('test@example.com');
        static::assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(RFC822Name $name): string
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
        static::assertSame(GeneralName::TAG_RFC822_NAME, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $name = RFC822Name::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(RFC822Name $ref, RFC822Name $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(RFC822Name $name)
    {
        static::assertIsString($name->string());
    }

    #[Test]
    #[Depends('create')]
    public function email(RFC822Name $name)
    {
        static::assertSame('test@example.com', $name->email());
    }
}
