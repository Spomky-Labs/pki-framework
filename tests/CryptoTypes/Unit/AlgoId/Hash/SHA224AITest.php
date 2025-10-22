<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;

/**
 * @internal
 */
final class SHA224AITest extends TestCase
{
    #[Test]
    public function encode(): Sequence
    {
        $ai = SHA224AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): SHA224AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(SHA224AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('encode')]
    public function decodeWithParams(Sequence $seq)
    {
        $seq = $seq->withInserted(1, NullType::create());
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(SHA224AlgorithmIdentifier::class, $ai);
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
