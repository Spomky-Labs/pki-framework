<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;

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
        $ai = new GenericAlgorithmIdentifier('1.3.6.1.3', new UnspecifiedType(new Integer(42)));
        $this->assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(GenericAlgorithmIdentifier $ai)
    {
        $this->assertEquals('1.3.6.1.3', $ai->name());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function parameters(GenericAlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(UnspecifiedType::class, $ai->parameters());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(GenericAlgorithmIdentifier $ai)
    {
        $this->assertInstanceOf(Sequence::class, $ai->toASN1());
    }
}
