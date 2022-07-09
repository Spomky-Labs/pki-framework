<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class DESEDE3CBCAITest extends TestCase
{
    private const IV = '12345678';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new DESEDE3CBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(DESEDE3CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     */
    public function testIV(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::IV, $ai->initializationVector());
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
        $ai = new DESEDE3CBCAlgorithmIdentifier();
        $this->expectException(\LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends testDecode
     */
    public function testBlockSize(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(8, $ai->blockSize());
    }

    /**
     * @depends testDecode
     */
    public function testKeySize(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(24, $ai->keySize());
    }

    public function testInvalidIVSizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new DESEDE3CBCAlgorithmIdentifier('1234');
    }

    /**
     * @depends testDecode
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
