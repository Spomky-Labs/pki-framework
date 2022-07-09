<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Asymmetric;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed448AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\X448AlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;

/**
 * @internal
 */
final class Curve448AITest extends TestCase
{
    /**
     * @test
     */
    public function encodeEd448(): Sequence
    {
        $ai = new Ed448AlgorithmIdentifier();
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encodeEd448
     *
     * @test
     */
    public function decodeEd448(Sequence $seq): Ed448AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(Ed448AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decodeEd448
     *
     * @test
     */
    public function ed448Name(Ed448AlgorithmIdentifier $ai)
    {
        $this->assertIsString($ai->name());
    }

    /**
     * @depends decodeEd448
     *
     * @test
     */
    public function ed448SupportsKeyAlgo(Ed448AlgorithmIdentifier $ai)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        $pk = PrivateKeyInfo::fromPEM($pem);
        $this->assertTrue($ai->supportsKeyAlgorithm($pk->algorithmIdentifier()));
    }

    /**
     * @test
     */
    public function encodeX448(): Sequence
    {
        $ai = new X448AlgorithmIdentifier();
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encodeX448
     *
     * @test
     */
    public function decodeX448(Sequence $seq): X448AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(X448AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decodeX448
     *
     * @test
     */
    public function x448Name(X448AlgorithmIdentifier $ai)
    {
        $this->assertIsString($ai->name());
    }
}
