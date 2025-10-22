<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;

/**
 * @internal
 */
final class SHA384WithRSAAITest extends TestCase
{
    #[Test]
    public function encode(): Sequence
    {
        $ai = SHA384WithRSAEncryptionAlgorithmIdentifier:: create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): SHA384WithRSAEncryptionAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(SHA384WithRSAEncryptionAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
