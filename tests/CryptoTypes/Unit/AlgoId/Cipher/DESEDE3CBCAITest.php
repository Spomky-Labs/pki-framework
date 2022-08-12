<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class DESEDE3CBCAITest extends TestCase
{
    private const IV = '12345678';

    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = DESEDE3CBCAlgorithmIdentifier::create(self::IV);
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
        static::assertInstanceOf(DESEDE3CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function iV(DESEDE3CBCAlgorithmIdentifier $ai)
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
        $ai = DESEDE3CBCAlgorithmIdentifier::create();
        $this->expectException(LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function blockSize(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(8, $ai->blockSize());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function keySize(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(24, $ai->keySize());
    }

    /**
     * @test
     */
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        DESEDE3CBCAlgorithmIdentifier::create('1234');
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
