<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;

/**
 * @internal
 */
final class MD5AITest extends TestCase
{
    #[Test]
    public function encode(): Sequence
    {
        $ai = MD5AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): MD5AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('encode')]
    public function decodeWithoutParams(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
    }

    #[Test]
    #[Depends('decode')]
    public function naverifyNameme(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
