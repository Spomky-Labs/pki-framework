<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;

/**
 * @internal
 */
final class MD5AITest extends TestCase
{
    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new MD5AlgorithmIdentifier();
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncode
     */
    public function testDecode(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testEncode
     */
    public function testDecodeWithoutParams(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
    }

    /**
     * @depends testDecode
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
