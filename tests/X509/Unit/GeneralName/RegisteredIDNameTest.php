<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\GeneralName;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\RegisteredID;

/**
 * @internal
 */
final class RegisteredIDNameTest extends TestCase
{
    /**
     * @test
     */
    public function create(): RegisteredID
    {
        $rid = RegisteredID::create('1.3.6.1.3.1');
        static::assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(RegisteredID $rid): string
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
    public function choiceTag($der): void
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
    public function recoded(RegisteredID $ref, RegisteredID $new): void
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(RegisteredID $rid): void
    {
        static::assertIsString($rid->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(RegisteredID $rid): void
    {
        static::assertEquals('1.3.6.1.3.1', $rid->oid());
    }
}
