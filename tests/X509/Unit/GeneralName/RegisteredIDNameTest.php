<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Tagged\ImplicitTagging;
use Sop\ASN1\Type\TaggedType;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\RegisteredID;

/**
 * @internal
 */
final class RegisteredIDNameTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $rid = new RegisteredID('1.3.6.1.3.1');
        static::assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(RegisteredID $rid)
    {
        $el = $rid->toASN1();
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
        static::assertEquals(GeneralName::TAG_REGISTERED_ID, $el->tag());
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
        $rid = RegisteredID::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(RegisteredID $ref, RegisteredID $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(RegisteredID $rid)
    {
        static::assertIsString($rid->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(RegisteredID $rid)
    {
        static::assertEquals('1.3.6.1.3.1', $rid->oid());
    }
}
