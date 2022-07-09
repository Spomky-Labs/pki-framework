<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class DESCBCAITest extends TestCase
{
    private const IV = '12345678';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new DESCBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(DESCBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     */
    public function testIV(DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::IV, $ai->initializationVector());
    }

    /**
     * @depends testDecode
     */
    public function testWithIV(DESCBCAlgorithmIdentifier $ai)
    {
        $ai2 = $ai->withInitializationVector('testtest');
        $this->assertNotEquals($ai2, $ai);
    }

    /**
     * @depends testEncode
     */
    public function testDecodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(\UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    public function testEncodeNoIVFail()
    {
        $ai = new DESCBCAlgorithmIdentifier();
        $this->expectException(\LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends testDecode
     */
    public function testBlockSize(DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->blockSize());
    }

    /**
     * @depends testDecode
     */
    public function testKeySize(DESCBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->keySize());
    }

    public function testInvalidIVSizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new DESCBCAlgorithmIdentifier('1234');
    }

    /**
     * @depends testDecode
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
