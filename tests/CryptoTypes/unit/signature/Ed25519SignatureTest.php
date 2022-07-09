<?php

declare(strict_types=1);

namespace unit\signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\Ed25519Signature;

/**
 * @group signature
 *
 * @internal
 */
class Ed25519SignatureTest extends TestCase
{
    public function testCreate(): Ed25519Signature
    {
        $sig = new Ed25519Signature(str_repeat("\0", 64));
        $this->assertInstanceOf(Ed25519Signature::class, $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     */
    public function testBitString(Ed25519Signature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }

    public function testInvalid()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be 64 octets/');
        new Ed25519Signature('');
    }
}
