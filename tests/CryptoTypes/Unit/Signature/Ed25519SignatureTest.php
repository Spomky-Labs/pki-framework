<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\Signature;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\Ed25519Signature;

/**
 * @internal
 */
final class Ed25519SignatureTest extends TestCase
{
    /**
     * @test
     */
    public function create(): Ed25519Signature
    {
        $sig = new Ed25519Signature(str_repeat("\0", 64));
        $this->assertInstanceOf(Ed25519Signature::class, $sig);
        return $sig;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function bitString(Ed25519Signature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }

    /**
     * @test
     */
    public function invalid()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be 64 octets/');
        new Ed25519Signature('');
    }
}
