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
use SpomkyLabs\Pki\X509\GeneralName\RegisteredID;

/**
 * @internal
 */
final class RegisteredIDNameTest extends TestCase
{
    #[Test]
    public function create(): RegisteredID
    {
        $rid = RegisteredID::create('1.3.6.1.3.1');
        static::assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }

    #[Test]
    #[Depends('create')]
    public function encode(RegisteredID $rid): string
    {
        $el = $rid->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function choiceTag($der): void
    {
        $el = TaggedType::fromDER($der);
        static::assertSame(GeneralName::TAG_REGISTERED_ID, $el->tag());
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): RegisteredID
    {
        $rid = RegisteredID::fromASN1(Element::fromDER($der));
        static::assertInstanceOf(RegisteredID::class, $rid);
        return $rid;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(RegisteredID $ref, RegisteredID $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(RegisteredID $rid): void
    {
        static::assertIsString($rid->string());
    }

    #[Test]
    #[Depends('create')]
    public function oID(RegisteredID $rid): void
    {
        static::assertSame('1.3.6.1.3.1', $rid->oid());
    }
}
