<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\X509\Certificate\UniqueIdentifier;

/**
 * @group certificate
 *
 * @internal
 */
class UniqueIdentifierTest extends TestCase
{
    final public const UID = 'urn:test';

    public function testCreate()
    {
        $id = UniqueIdentifier::fromString(self::UID);
        $this->assertInstanceOf(UniqueIdentifier::class, $id);
        return $id;
    }

    /**
     * @depends testCreate
     */
    public function testEncode(UniqueIdentifier $id)
    {
        $bs = $id->toASN1();
        $this->assertInstanceOf(BitString::class, $bs);
        return $bs->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $id = UniqueIdentifier::fromASN1(BitString::fromDER($der));
        $this->assertInstanceOf(UniqueIdentifier::class, $id);
        return $id;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     */
    public function testRecoded(UniqueIdentifier $ref, UniqueIdentifier $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     */
    public function testString(UniqueIdentifier $id)
    {
        $this->assertEquals(self::UID, $id->string());
    }

    /**
     * @depends testCreate
     */
    public function testBitString(UniqueIdentifier $id)
    {
        $this->assertInstanceOf(BitString::class, $id->bitString());
    }
}
