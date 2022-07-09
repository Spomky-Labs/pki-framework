<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Cipher;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class RC2CBCAITest extends TestCase
{
    private const IV = '12345678';

    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = new RC2CBCAlgorithmIdentifier(64, self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @test
     */
    public function decodeRFC2268OnlyIV()
    {
        $seq = new Sequence(new ObjectIdentifier(AlgorithmIdentifier::OID_RC2_CBC), new OctetString(self::IV));
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function effectiveKeyBits(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(64, $ai->effectiveKeyBits());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function iV(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(self::IV, $ai->initializationVector());
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @test
     */
    public function encodeNoIVFail()
    {
        $ai = new RC2CBCAlgorithmIdentifier();
        $this->expectException(LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function blockSize(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(8, $ai->blockSize());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function keySize(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(8, $ai->keySize());
    }

    /**
     * @test
     */
    public function encodeLargeKey()
    {
        $ai = new RC2CBCAlgorithmIdentifier(512, self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encodeLargeKey
     *
     * @test
     */
    public function decodeLargeKey(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
    }

    /**
     * @test
     */
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        new RC2CBCAlgorithmIdentifier(64, '1234');
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function name(AlgorithmIdentifier $algo)
    {
        static::assertIsString($algo->name());
    }
}
