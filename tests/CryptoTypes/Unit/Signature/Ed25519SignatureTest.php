<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\Signature\Ed25519Signature;

/**
 * @internal
 */
final class Ed25519SignatureTest extends TestCase
{
    #[Test]
    public function create(): Ed25519Signature
    {
        $sig = Ed25519Signature::create(str_repeat("\0", 64));
        static::assertInstanceOf(Ed25519Signature::class, $sig);
        return $sig;
    }

    #[Test]
    #[Depends('create')]
    public function bitString(Ed25519Signature $sig)
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }

    #[Test]
    public function invalid()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be 64 octets/');
        Ed25519Signature::create('');
    }
}
