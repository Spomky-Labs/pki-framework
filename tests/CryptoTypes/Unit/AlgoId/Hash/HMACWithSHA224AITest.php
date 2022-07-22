<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Hash;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA224AlgorithmIdentifier;

/**
 * @internal
 */
final class HMACWithSHA224AITest extends TestCase
{
    /**
     * @return Sequence
     *
     * @test
     */
    public function encode()
    {
        $ai = HMACWithSHA224AlgorithmIdentifier::create();
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
        static::assertInstanceOf(HMACWithSHA224AlgorithmIdentifier::class, $ai);
        return $ai;
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
