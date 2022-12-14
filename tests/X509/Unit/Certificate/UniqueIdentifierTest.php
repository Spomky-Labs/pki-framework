<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;

/**
 * @internal
 */
final class UniqueIdentifierTest extends TestCase
{
    final public const UID = 'urn:test';

    /**
     * @test
     */
    public function create()
    {
        $id = UniqueIdentifier::fromString(self::UID);
        static::assertInstanceOf(UniqueIdentifier::class, $id);
        return $id;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(UniqueIdentifier $id)
    {
        $bs = $id->toASN1();
        static::assertInstanceOf(BitString::class, $bs);
        return $bs->toDER();
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
        $id = UniqueIdentifier::fromASN1(BitString::fromDER($der));
        static::assertInstanceOf(UniqueIdentifier::class, $id);
        return $id;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(UniqueIdentifier $ref, UniqueIdentifier $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(UniqueIdentifier $id)
    {
        static::assertEquals(self::UID, $id->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(UniqueIdentifier $id)
    {
        static::assertInstanceOf(BitString::class, $id->bitString());
    }
}
