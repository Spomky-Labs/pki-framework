<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;

/**
 * @internal
 */
final class SHA512AITest extends TestCase
{
    #[Test]
    public function encode(): Sequence
    {
        $ai = SHA512AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): SHA512AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(SHA512AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
