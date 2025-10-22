<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Cipher;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class RC2CBCAITest extends TestCase
{
    private const IV = '12345678';

    #[Test]
    public function encode(): Sequence
    {
        $ai = RC2CBCAlgorithmIdentifier::create(64, self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): RC2CBCAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    public function decodeRFC2268OnlyIV()
    {
        $seq = Sequence::create(
            ObjectIdentifier::create(AlgorithmIdentifier::OID_RC2_CBC),
            OctetString::create(self::IV)
        );
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
    }

    #[Test]
    #[Depends('decode')]
    public function effectiveKeyBits(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(64, $ai->effectiveKeyBits());
    }

    #[Test]
    #[Depends('decode')]
    public function iV(RC2CBCAlgorithmIdentifier $ai)
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
    public function blockSize(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(8, $ai->blockSize());
    }

    #[Test]
    #[Depends('decode')]
    public function keySize(RC2CBCAlgorithmIdentifier $ai)
    {
        static::assertSame(8, $ai->keySize());
    }

    #[Test]
    public function encodeLargeKey()
    {
        $ai = RC2CBCAlgorithmIdentifier::create(512, self::IV);
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encodeLargeKey')]
    public function decodeLargeKey(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(RC2CBCAlgorithmIdentifier::class, $ai);
    }

    #[Test]
    public function invalidIVSizeFail()
    {
        $this->expectException(UnexpectedValueException::class);
        RC2CBCAlgorithmIdentifier::create(64, '1234');
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
