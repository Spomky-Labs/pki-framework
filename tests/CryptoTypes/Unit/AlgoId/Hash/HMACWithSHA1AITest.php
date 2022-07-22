<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA1AlgorithmIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class HMACWithSHA1AITest extends TestCase
{
    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = HMACWithSHA1AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decode(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(HMACWithSHA1AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decodeWithParamsFail(Sequence $seq)
    {
        $seq = $seq->withInserted(1, new NullType());
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }

    /**
     * @depends decode
     *
     * @test
     */
    public function name(AlgorithmIdentifier $algo)
    {
        static::assertIsString($algo->name());
    }
}
