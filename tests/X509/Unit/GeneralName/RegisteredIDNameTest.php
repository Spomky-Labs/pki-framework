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
        $this->assertInstanceOf(RegisteredID::class, $rid);
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
        $this->assertEquals(GeneralName::TAG_REGISTERED_ID, $el->tag());
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
        $this->assertInstanceOf(RegisteredID::class, $rid);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(RegisteredID $rid)
    {
        $this->assertIsString($rid->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(RegisteredID $rid)
    {
        $this->assertEquals('1.3.6.1.3.1', $rid->oid());
    }
}
