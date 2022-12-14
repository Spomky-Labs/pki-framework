<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

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

    /**
     * @test
     */
    public function create()
    {
        $uri = UniformResourceIdentifier::create(self::URI);
        static::assertInstanceOf(UniformResourceIdentifier::class, $uri);
        return $uri;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(UniformResourceIdentifier $uri)
    {
        $el = $uri->toASN1();
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
        static::assertEquals(GeneralName::TAG_URI, $el->tag());
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
        $uri = UniformResourceIdentifier::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(UniformResourceIdentifier::class, $uri);
        return $uri;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(UniformResourceIdentifier $ref, UniformResourceIdentifier $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(UniformResourceIdentifier $uri)
    {
        static::assertEquals(self::URI, $uri->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function uRI(UniformResourceIdentifier $uri)
    {
        static::assertEquals(self::URI, $uri->uri());
    }
}
