<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;

/**
 * @internal
 */
final class ECDSAAITest extends TestCase
{
    /**
     * @test
     */
    public function supportsKeyAlgorithm()
    {
        $sig_algo = ECDSAWithSHA1AlgorithmIdentifier::create();
        $key_algo = ECPublicKeyAlgorithmIdentifier::create(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME192V1);
        static::assertTrue($sig_algo->supportsKeyAlgorithm($key_algo));
    }

    /**
     * @test
     */
    public function doesntSupportsKeyAlgorithm()
    {
        $sig_algo = ECDSAWithSHA1AlgorithmIdentifier::create();
        $key_algo = RSAEncryptionAlgorithmIdentifier::create();
        static::assertFalse($sig_algo->supportsKeyAlgorithm($key_algo));
    }
}
