<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\RFC822Name;

/**
 * @internal
 */
final class RFC822NameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = new RFC822Name('test@example.com');
        $this->assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(RFC822Name $name)
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
        $this->assertEquals(GeneralName::TAG_RFC822_NAME, $el->tag());
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
        $name = RFC822Name::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(RFC822Name::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(RFC822Name $ref, RFC822Name $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(RFC822Name $name)
    {
        $this->assertIsString($name->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function email(RFC822Name $name)
    {
        $this->assertEquals('test@example.com', $name->email());
    }
}
