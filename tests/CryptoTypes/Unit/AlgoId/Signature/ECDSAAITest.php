<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;

/**
 * @internal
 */
final class ECDSAAITest extends TestCase
{
    public function testSupportsKeyAlgorithm()
    {
        $sig_algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $key_algo = new ECPublicKeyAlgorithmIdentifier(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME192V1);
        $this->assertTrue($sig_algo->supportsKeyAlgorithm($key_algo));
    }

    public function testDoesntSupportsKeyAlgorithm()
    {
        $sig_algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $key_algo = new RSAEncryptionAlgorithmIdentifier();
        $this->assertFalse($sig_algo->supportsKeyAlgorithm($key_algo));
    }
}
