<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;

/**
 * @internal
 */
final class AES256CBCAITest extends TestCase
{
    private const IV = '0123456789abcdef';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new AES256CBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(AES256CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     */
    public function testIV(AES256CBCAlgorithmIdentifier $ai)
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
        $ai = new AES256CBCAlgorithmIdentifier();
        $this->expectException(\LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends testDecode
     */
    public function testBlockSize(AES256CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(16, $ai->blockSize());
    }

    /**
     * @depends testDecode
     */
    public function testKeySize(AES256CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(32, $ai->keySize());
    }

    public function testInvalidIVSizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new AES256CBCAlgorithmIdentifier('1234');
    }

    /**
     * @depends testDecode
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
