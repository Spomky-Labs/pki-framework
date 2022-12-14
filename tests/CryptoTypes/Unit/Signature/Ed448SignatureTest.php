<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\Signature\Ed448Signature;

/**
 * @internal
 */
final class Ed448SignatureTest extends TestCase
{
    #[Test]
    public function create(): Ed448Signature
    {
        $sig = Ed448Signature::create(str_repeat("\0", 114));
        static::assertInstanceOf(Ed448Signature::class, $sig);
        return $sig;
    }

    #[Test]
    #[Depends('create')]
    public function bitString(Ed448Signature $sig): void
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }

    #[Test]
    public function invalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/must be 114 octets/');
        Ed448Signature::create('');
    }
}
