<?php

declare(strict_types=1);

namespace unit\signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed25519AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\Ed448AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Signature\ECSignature;
use Sop\CryptoTypes\Signature\Ed25519Signature;
use Sop\CryptoTypes\Signature\Ed448Signature;
use Sop\CryptoTypes\Signature\GenericSignature;
use Sop\CryptoTypes\Signature\RSASignature;
use Sop\CryptoTypes\Signature\Signature;

/**
 * @group signature
 *
 * @internal
 */
class SignatureTest extends TestCase
{
    public function testFromRSAAlgo()
    {
        $sig = Signature::fromSignatureData('test',
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(RSASignature::class, $sig);
    }

    public function testFromECAlgo()
    {
        $seq = new Sequence(new Integer(1), new Integer(2));
        $sig = Signature::fromSignatureData($seq->toDER(),
            new ECDSAWithSHA1AlgorithmIdentifier());
        $this->assertInstanceOf(ECSignature::class, $sig);
    }

    public function testFromEd25519Algo()
    {
        $sig = Signature::fromSignatureData(str_repeat("\0", 64),
            new Ed25519AlgorithmIdentifier());
        $this->assertInstanceOf(Ed25519Signature::class, $sig);
    }

    public function testFromEd448Algo()
    {
        $sig = Signature::fromSignatureData(str_repeat("\0", 114),
            new Ed448AlgorithmIdentifier());
        $this->assertInstanceOf(Ed448Signature::class, $sig);
    }

    public function testFromUnknownAlgo()
    {
        $sig = Signature::fromSignatureData('',
            new GenericAlgorithmIdentifier('1.3.6.1.3'));
        $this->assertInstanceOf(GenericSignature::class, $sig);
    }
}
