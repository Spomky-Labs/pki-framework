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

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class Curve25519AITest extends TestCase
{
    public function testEncodeEd25519(): Sequence
    {
        $ai = new Ed25519AlgorithmIdentifier();
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncodeEd25519
     */
    public function testDecodeEd25519(Sequence $seq): Ed25519AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(Ed25519AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecodeEd25519
     */
    public function testEd25519Name(Ed25519AlgorithmIdentifier $ai)
    {
        $this->assertIsString($ai->name());
    }

    /**
     * @depends testDecodeEd25519
     */
    public function testEd25519SupportsKeyAlgo(Ed25519AlgorithmIdentifier $ai)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rfc8410/ed25519_private_key.pem');
        $pk = PrivateKeyInfo::fromPEM($pem);
        $this->assertTrue($ai->supportsKeyAlgorithm($pk->algorithmIdentifier()));
    }

    public function testEncodeX25519(): Sequence
    {
        $ai = new X25519AlgorithmIdentifier();
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncodeX25519
     */
    public function testDecodeX25519(Sequence $seq): X25519AlgorithmIdentifier
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(X25519AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testDecodeX25519
     */
    public function testX25519Name(X25519AlgorithmIdentifier $ai)
    {
        $this->assertIsString($ai->name());
    }

    public function testEd25519MustHaveNoParams()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/must be absent/');
        Ed25519AlgorithmIdentifier::fromASN1Params(
            UnspecifiedType::fromElementBase(new NullType()));
    }

    public function testX25519MustHaveNoParams()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/must be absent/');
        X25519AlgorithmIdentifier::fromASN1Params(
            UnspecifiedType::fromElementBase(new NullType()));
    }
}
