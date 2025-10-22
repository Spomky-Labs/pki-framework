<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class ECDSAWithSHA1AITest extends TestCase
{
    #[Test]
    public function encode(): Sequence
    {
        $ai = ECDSAWithSHA1AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encode')]
    public function decode(Sequence $seq): ECDSAWithSHA1AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(ECDSAWithSHA1AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('encode')]
    public function decodeWithParamsFail(Sequence $seq)
    {
        $seq = $seq->withInserted(1, NullType::create());
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    #[Test]
    #[Depends('decode')]
    public function verifyName(?AlgorithmIdentifier $algo = null)
    {
        static::assertIsString($algo->name());
    }
}
