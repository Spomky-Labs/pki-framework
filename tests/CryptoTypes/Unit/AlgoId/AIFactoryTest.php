<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierFactory;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifierProvider;
use Sop\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class AIFactoryTest extends TestCase
{
    public function testProvider()
    {
        $factory = new AlgorithmIdentifierFactory(new AIFactoryTestProvider());
        $seq = new Sequence(new ObjectIdentifier('1.3.6.1.3'));
        $ai = $factory->parse($seq);
        $this->assertInstanceOf(AIFactoryTestCustomAlgo::class, $ai);
    }

    public function testProviderNoMatch()
    {
        $factory = new AlgorithmIdentifierFactory(new AIFactoryTestProvider());
        $seq = new Sequence(new ObjectIdentifier('1.3.6.1.3.1'));
        $ai = $factory->parse($seq);
        $this->assertNotInstanceOf(AIFactoryTestCustomAlgo::class, $ai);
    }
}
