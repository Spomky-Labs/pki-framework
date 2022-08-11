<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

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
    /**
     * @test
     */
    public function create()
    {
        $name = new OtherName('1.3.6.1.3.1', NullType::create());
        static::assertInstanceOf(OtherName::class, $name);
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
        static::assertEquals(GeneralName::TAG_OTHER_NAME, $el->tag());
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
        static::assertInstanceOf(OtherName::class, $name);
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
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(OtherName $name)
    {
        static::assertIsString($name->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(OtherName $name)
    {
        static::assertEquals('1.3.6.1.3.1', $name->type());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function value(OtherName $name)
    {
        static::assertEquals(NullType::create(), $name->value());
    }
}
