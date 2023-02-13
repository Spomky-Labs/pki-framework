<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Asymmetric;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\X448AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;

/**
 * @internal
 */
final class Curve448AITest extends TestCase
{
    #[Test]
    public function encodeEd448(): Sequence
    {
        $ai = Ed448AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encodeEd448')]
    public function decodeEd448(Sequence $seq): Ed448AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(Ed448AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decodeEd448')]
    public function ed448Name(Ed448AlgorithmIdentifier $ai)
    {
        static::assertIsString($ai->name());
    }

    #[Test]
    #[Depends('decodeEd448')]
    public function ed448SupportsKeyAlgo(Ed448AlgorithmIdentifier $ai)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed448_private_key.pem');
        $pk = PrivateKeyInfo::fromPEM($pem);
        static::assertTrue($ai->supportsKeyAlgorithm($pk->algorithmIdentifier()));
    }

    #[Test]
    public function encodeX448(): Sequence
    {
        $ai = X448AlgorithmIdentifier::create();
        $seq = $ai->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    #[Test]
    #[Depends('encodeX448')]
    public function decodeX448(Sequence $seq): X448AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        static::assertInstanceOf(X448AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('decodeX448')]
    public function x448Name(X448AlgorithmIdentifier $ai)
    {
        static::assertIsString($ai->name());
    }
}
