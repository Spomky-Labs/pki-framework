<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\AES192CBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class AES192CBCAITest extends TestCase
{
    private const IV = '0123456789abcdef';

    #[Test]
    public function encode(): Sequence
    {
        $ai = AES192CBCAlgorithmIdentifier::create(self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): AES192CBCAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(AES192CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function iV(AES192CBCAlgorithmIdentifier $ai)
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
    public function blockSize(AES192CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(16, $ai->blockSize());
    }

    #[Test]
    #[Depends('decode')]
    public function keySize(AES192CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(24, $ai->keySize());
    }

    #[Test]
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        AES192CBCAlgorithmIdentifier::create('1234');
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
