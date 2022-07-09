<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\X509\Certificate\UniqueIdentifier;

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
        $this->assertInstanceOf(UniqueIdentifier::class, $id);
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
        $this->assertInstanceOf(BitString::class, $bs);
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
        $this->assertInstanceOf(UniqueIdentifier::class, $id);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function string(UniqueIdentifier $id)
    {
        $this->assertEquals(self::UID, $id->string());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(UniqueIdentifier $id)
    {
        $this->assertInstanceOf(BitString::class, $id->bitString());
    }
}
