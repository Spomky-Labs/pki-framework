<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class DESCBCAITest extends TestCase
{
    private const IV = '12345678';

    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = new DESCBCAlgorithmIdentifier(self::IV);
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
        static::assertInstanceOf(DESCBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function iV(DESCBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(self::IV, $ai->initializationVector());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function withIV(DESCBCAlgorithmIdentifier $ai)
    {
        $ai2 = $ai->withInitializationVector('testtest');
        static::assertNotEquals($ai2, $ai);
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
        $ai = new DESCBCAlgorithmIdentifier();
        $this->expectException(LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function blockSize(DESCBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(8, $ai->blockSize());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function keySize(DESCBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(8, $ai->keySize());
    }

    /**
     * @test
     */
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        new DESCBCAlgorithmIdentifier('1234');
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
