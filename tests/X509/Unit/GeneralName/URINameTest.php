<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\UniformResourceIdentifier;

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
        $uri = new UniformResourceIdentifier(self::URI);
        $this->assertInstanceOf(UniformResourceIdentifier::class, $uri);
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
        $this->assertEquals(GeneralName::TAG_URI, $el->tag());
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
        $this->assertInstanceOf(UniformResourceIdentifier::class, $uri);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(UniformResourceIdentifier $uri)
    {
        $this->assertEquals(self::URI, $uri->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function uRI(UniformResourceIdentifier $uri)
    {
        $this->assertEquals(self::URI, $uri->uri());
    }
}
