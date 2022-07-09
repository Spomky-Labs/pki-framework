<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\TestCase;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;

/**
 * @internal
 */
final class RSASigAITest extends TestCase
{
    /**
     * @test
     */
    public function supportsKeyAlgorithm()
    {
        $sig_algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $key_algo = new RSAEncryptionAlgorithmIdentifier();
        static::assertTrue($sig_algo->supportsKeyAlgorithm($key_algo));
    }

    /**
     * @test
     */
    public function doesntSupportsKeyAlgorithm()
    {
        $sig_algo = new SHA1WithRSAEncryptionAlgorithmIdentifier();
        $key_algo = new ECPublicKeyAlgorithmIdentifier(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME192V1);
        static::assertFalse($sig_algo->supportsKeyAlgorithm($key_algo));
    }
}
