<?php

declare(strict_types=1);

namespace Sop\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\CryptoTypes\Signature\Ed448Signature;

/**
 * @group signature
 *
 * @internal
 */
class Ed448SignatureTest extends TestCase
{
    public function testCreate(): Ed448Signature
    {
        $sig = new Ed448Signature(str_repeat("\0", 114));
        $this->assertInstanceOf(Ed448Signature::class, $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     */
    public function testBitString(Ed448Signature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }

    public function testInvalid()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be 114 octets/');
        new Ed448Signature('');
    }
}
