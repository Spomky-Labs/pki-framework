<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\MD4WithRSAEncryptionAlgorithmIdentifier;

/**
 * @internal
 */
final class MD4WithRSAAITest extends TestCase
{
    /**
     * @return Sequence
     */
    #[Test]
    public function encode()
    {
        $ai = MD4WithRSAEncryptionAlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(MD4WithRSAEncryptionAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function name(AlgorithmIdentifier $algo)
    {
        static::assertIsString($algo->name());
    }
}
