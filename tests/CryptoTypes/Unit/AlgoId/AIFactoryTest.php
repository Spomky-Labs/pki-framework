<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierFactory;

/**
 * @internal
 */
final class AIFactoryTest extends TestCase
{
    /**
     * @test
     */
    public function provider()
    {
        $factory = new AlgorithmIdentifierFactory(new AIFactoryTestProvider());
        $seq = new Sequence(new ObjectIdentifier('1.3.6.1.3'));
        $ai = $factory->parse($seq);
        static::assertInstanceOf(AIFactoryTestCustomAlgo::class, $ai);
    }

    /**
     * @test
     */
    public function providerNoMatch()
    {
        $factory = new AlgorithmIdentifierFactory(new AIFactoryTestProvider());
        $seq = new Sequence(new ObjectIdentifier('1.3.6.1.3.1'));
        $ai = $factory->parse($seq);
        static::assertNotInstanceOf(AIFactoryTestCustomAlgo::class, $ai);
    }
}
