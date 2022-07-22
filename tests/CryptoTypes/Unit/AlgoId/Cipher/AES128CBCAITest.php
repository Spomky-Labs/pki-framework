<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES128CBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class AES128CBCAITest extends TestCase
{
    private const IV = '0123456789abcdef';

    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = AES128CBCAlgorithmIdentifier::create(self::IV);
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
        static::assertInstanceOf(AES128CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function iV(AES128CBCAlgorithmIdentifier $ai)
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
        $ai = AES128CBCAlgorithmIdentifier::create();
        $this->expectException(LogicException::class);
        $ai->toASN1();
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function blockSize(AES128CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(16, $ai->blockSize());
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function keySize(AES128CBCAlgorithmIdentifier $ai)
    {
        static::assertEquals(16, $ai->keySize());
    }

    /**
     * @test
     */
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        AES128CBCAlgorithmIdentifier::create('1234');
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
