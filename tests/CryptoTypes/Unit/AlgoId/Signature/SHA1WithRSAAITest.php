<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class SHA1WithRSAAITest extends TestCase
{
    /**
     * @test
     */
    public function encode(): Sequence
    {
        $ai = SHA1WithRSAEncryptionAlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(Sequence $seq): AlgorithmIdentifier|SHA1WithRSAEncryptionAlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(SHA1WithRSAEncryptionAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decodeNoParamsFail(Sequence $seq): void
    {
        $seq = $seq->withoutElement(1);
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decodeInvalidParamsFail(Sequence $seq): void
    {
        $seq = $seq->withReplaced(1, Sequence::create());
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function name(AlgorithmIdentifier $algo): void
    {
        static::assertIsString($algo->name());
    }
}
