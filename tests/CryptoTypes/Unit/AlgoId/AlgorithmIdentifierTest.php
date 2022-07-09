<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId;

use BadMethodCallException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * @internal
 */
final class AlgorithmIdentifierTest extends TestCase
{
    private static $_unknownASN1;

    public static function setUpBeforeClass(): void
    {
        self::$_unknownASN1 = new Sequence(new ObjectIdentifier('1.3.6.1.3', new NullType()));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_unknownASN1 = null;
    }

    /**
     * @return AlgorithmIdentifier
     *
     * @test
     */
    public function fromUnknownASN1()
    {
        $ai = AlgorithmIdentifier::fromASN1(self::$_unknownASN1);
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends fromUnknownASN1
     *
     * @test
     */
    public function encodeUnknown(GenericAlgorithmIdentifier $ai)
    {
        $seq = $ai->toASN1();
        static::assertEquals(self::$_unknownASN1, $seq);
    }

    /**
     * @test
     */
    public function specificAlgoBadCall()
    {
        $this->expectException(BadMethodCallException::class);
        SpecificAlgorithmIdentifier::fromASN1Params();
    }

    /**
     * @depends fromUnknownASN1
     *
     * @test
     */
    public function name(AlgorithmIdentifier $algo)
    {
        static::assertIsString($algo->name());
    }
}
