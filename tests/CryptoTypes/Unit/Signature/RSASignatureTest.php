<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\RSASignature;

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
        $this->assertInstanceOf(RSASignature::class, $sig);
        return $sig;
    }

    /**
     * @depends fromSignatureString
     *
     * @test
     */
    public function bitString(RSASignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
}
