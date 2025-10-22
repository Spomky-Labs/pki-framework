<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
    public function encode(): Sequence
    {
        $ai = DESEDE3CBCAlgorithmIdentifier::create(self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): DESEDE3CBCAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(DESEDE3CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function iV(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(self::IV, $ai->initializationVector());
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
    public function blockSize(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(8, $ai->blockSize());
    }

    #[Test]
    #[Depends('decode')]
    public function keySize(DESEDE3CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(24, $ai->keySize());
    }

    #[Test]
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        DESEDE3CBCAlgorithmIdentifier::create('1234');
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
