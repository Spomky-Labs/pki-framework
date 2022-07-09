<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\Signature\RSASignature;

/**
 * @internal
 */
final class RSASignatureTest extends TestCase
{
    /**
     * @return RSASignature
     *
     * @test
     */
    public function fromSignatureString()
    {
        $sig = RSASignature::fromSignatureString('test');
        static::assertInstanceOf(RSASignature::class, $sig);
        return $sig;
    }

    /**
     * @depends fromSignatureString
     *
     * @test
     */
    public function bitString(RSASignature $sig)
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }
}
