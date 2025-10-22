<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;

/**
 * @internal
 */
final class ECDSAWithSHA224AITest extends TestCase
{
    #[Test]
    public function encode(): Sequence
    {
        $ai = ECDSAWithSHA224AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): ECDSAWithSHA224AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(ECDSAWithSHA224AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
