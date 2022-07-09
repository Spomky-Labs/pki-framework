<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\OtherName;

/**
 * @internal
 */
final class OtherNameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $name = new OtherName('1.3.6.1.3.1', new NullType());
        $this->assertInstanceOf(OtherName::class, $name);
        return $name;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(OtherName $name)
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
        $this->assertEquals(GeneralName::TAG_OTHER_NAME, $el->tag());
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
        $name = OtherName::fromASN1(Element::fromDER($der));
        $this->assertInstanceOf(OtherName::class, $name);
        return $name;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(OtherName $ref, OtherName $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(OtherName $name)
    {
        $this->assertIsString($name->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(OtherName $name)
    {
        $this->assertEquals('1.3.6.1.3.1', $name->type());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function value(OtherName $name)
    {
        $this->assertEquals(new NullType(), $name->value());
    }
}
