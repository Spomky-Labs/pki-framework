<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;

/**
 * @internal
 */
final class AlgorithmIdentifierTest extends TestCase
{
    private static ?Sequence $_unknownASN1 = null;

    public static function setUpBeforeClass(): void
    {
        self::$_unknownASN1 = Sequence::create(ObjectIdentifier::create('1.3.6.1.3'/*, NullType::create()*/));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_unknownASN1 = null;
    }

    /**
     * @return AlgorithmIdentifier
     */
    #[Test]
    public function fromUnknownASN1(): GenericAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1(self::$_unknownASN1);
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('fromUnknownASN1')]
    public function encodeUnknown(GenericAlgorithmIdentifier $ai): void
    {
        $seq = $ai->toASN1();
        static::assertEquals(self::$_unknownASN1, $seq);
    }

    #[Test]
    #[Depends('fromUnknownASN1')]
    public function verifyName(?AlgorithmIdentifier $algo = null): void
    {
        static::assertIsString($algo->name());
    }
}
