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
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class URINameTest extends TestCase
{
    public const URI = 'urn:test';

    #[Test]
    public function create(): UniformResourceIdentifier
    {
        $uri = UniformResourceIdentifier::create(self::URI);
        static::assertInstanceOf(UniformResourceIdentifier::class, $uri);
        return $uri;
    }

    #[Test]
    #[Depends('create')]
    public function encode(UniformResourceIdentifier $uri): string
    {
        $el = $uri->toASN1();
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
        static::assertSame(GeneralName::TAG_URI, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $uri = UniformResourceIdentifier::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(UniformResourceIdentifier::class, $uri);
        return $uri;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(UniformResourceIdentifier $ref, UniformResourceIdentifier $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(UniformResourceIdentifier $uri)
    {
        static::assertSame(self::URI, $uri->string());
    }

    #[Test]
    #[Depends('create')]
    public function uRI(UniformResourceIdentifier $uri)
    {
        static::assertSame(self::URI, $uri->uri());
    }
}
