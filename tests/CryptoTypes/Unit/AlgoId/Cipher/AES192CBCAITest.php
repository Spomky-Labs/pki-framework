<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Cipher;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class AES192CBCAITest extends TestCase
{
    private const IV = '0123456789abcdef';

    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new AES192CBCAlgorithmIdentifier(self::IV);
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
        $this->assertInstanceOf(AES192CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecode
     */
    public function testIV(AES192CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(self::IV, $ai->initializationVector());
    }

    /**
     * @depends testEncode
     */
    public function testDecodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    public function testEncodeNoIVFail()
    {
        $ai = new AES192CBCAlgorithmIdentifier();
        $this->expectException(LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends testDecode
     */
    public function testBlockSize(AES192CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(16, $ai->blockSize());
    }

    /**
     * @depends testDecode
     */
    public function testKeySize(AES192CBCAlgorithmIdentifier $ai)
    {
        $this->assertEquals(24, $ai->keySize());
    }

    public function testInvalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        new AES192CBCAlgorithmIdentifier('1234');
    }

    /**
     * @depends testDecode
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
