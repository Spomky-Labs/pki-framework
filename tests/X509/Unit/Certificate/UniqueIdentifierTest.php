<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;

/**
 * @internal
 */
final class UniqueIdentifierTest extends TestCase
{
    final public const UID = 'urn:test';

    #[Test]
    public function create(): UniqueIdentifier
    {
        $id = UniqueIdentifier::fromString(self::UID);
        static::assertInstanceOf(UniqueIdentifier::class, $id);
        return $id;
    }

    #[Test]
    #[Depends('create')]
    public function encode(UniqueIdentifier $id): string
    {
        $bs = $id->toASN1();
        static::assertInstanceOf(BitString::class, $bs);
        return $bs->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): UniqueIdentifier
    {
        $id = UniqueIdentifier::fromASN1(BitString::fromDER($der));
        static::assertInstanceOf(UniqueIdentifier::class, $id);
        return $id;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(UniqueIdentifier $ref, UniqueIdentifier $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function string(UniqueIdentifier $id)
    {
        static::assertSame(self::UID, $id->string());
    }

    #[Test]
    #[Depends('create')]
    public function bitString(UniqueIdentifier $id)
    {
        static::assertInstanceOf(BitString::class, $id->bitString());
    }
}
