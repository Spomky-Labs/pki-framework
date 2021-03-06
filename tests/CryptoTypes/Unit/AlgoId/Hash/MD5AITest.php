<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;

/**
 * @internal
 */
final class MD5AITest extends TestCase
{
    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = new MD5AlgorithmIdentifier();
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
        static::assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends encode
     *
     * @test
     */
    public function decodeWithoutParams(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
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
