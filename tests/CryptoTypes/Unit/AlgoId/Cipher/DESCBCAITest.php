<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
    public function encode(): Sequence
    {
        $ai = DESCBCAlgorithmIdentifier::create(self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): DESCBCAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(DESCBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function iV(DESCBCAlgorithmIdentifier $ai)
    {
        static::assertSame(self::IV, $ai->initializationVector());
    }

    #[Test]
    #[Depends('decode')]
    public function withIV(DESCBCAlgorithmIdentifier $ai)
    {
        $ai2 = $ai->withInitializationVector('testtest');
        static::assertNotEquals($ai2, $ai);
    }

    #[Test]
    #[Depends('encode')]
    public function decodeNoParamsFail(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    #[Test]
    #[Depends('decode')]
    public function blockSize(DESCBCAlgorithmIdentifier $ai)
    {
        static::assertSame(8, $ai->blockSize());
    }

    #[Test]
    #[Depends('decode')]
    public function keySize(DESCBCAlgorithmIdentifier $ai)
    {
        static::assertSame(8, $ai->keySize());
    }

    #[Test]
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        DESCBCAlgorithmIdentifier::create('1234');
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
