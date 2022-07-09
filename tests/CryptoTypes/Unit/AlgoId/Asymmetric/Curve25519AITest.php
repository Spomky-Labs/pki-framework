<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Asymmetric;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed25519AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\X25519AlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use UnexpectedValueException;

/**
 * @internal
 */
final class Curve25519AITest extends TestCase
{
    /**
     * @test
     */
    public function encodeEd25519(): Sequence
    {
        $ai = new Ed25519AlgorithmIdentifier();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encodeEd25519
     *
     * @test
     */
    public function decodeEd25519(Sequence $seq): Ed25519AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(Ed25519AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decodeEd25519
     *
     * @test
     */
    public function ed25519Name(Ed25519AlgorithmIdentifier $ai)
    {
        static::assertIsString($ai->name());
    }

    /**
     * @depends decodeEd25519
     *
     * @test
     */
    public function ed25519SupportsKeyAlgo(Ed25519AlgorithmIdentifier $ai)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pk = PrivateKeyInfo::fromPEM($pem);
        static::assertTrue($ai->supportsKeyAlgorithm($pk->algorithmIdentifier()));
    }

    /**
     * @test
     */
    public function encodeX25519(): Sequence
    {
        $ai = new X25519AlgorithmIdentifier();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends encodeX25519
     *
     * @test
     */
    public function decodeX25519(Sequence $seq): X25519AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(X25519AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends decodeX25519
     *
     * @test
     */
    public function x25519Name(X25519AlgorithmIdentifier $ai)
    {
        static::assertIsString($ai->name());
    }

    /**
     * @test
     */
    public function ed25519MustHaveNoParams()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/must be absent/');
        Ed25519AlgorithmIdentifier::fromASN1Params(UnspecifiedType::fromElementBase(new NullType()));
    }

    /**
     * @test
     */
    public function x25519MustHaveNoParams()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/must be absent/');
        X25519AlgorithmIdentifier::fromASN1Params(UnspecifiedType::fromElementBase(new NullType()));
    }
}
