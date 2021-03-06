<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;

/**
 * @internal
 */
final class GenericAlgorithmIdentifierTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ai = new GenericAlgorithmIdentifier('1.3.6.1.3', UnspecifiedType::create(new Integer(42)));
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(GenericAlgorithmIdentifier $ai)
    {
        static::assertEquals('1.3.6.1.3', $ai->name());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function parameters(GenericAlgorithmIdentifier $ai)
    {
        static::assertInstanceOf(UnspecifiedType::class, $ai->parameters());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(GenericAlgorithmIdentifier $ai)
    {
        static::assertInstanceOf(Sequence::class, $ai->toASN1());
    }
}
