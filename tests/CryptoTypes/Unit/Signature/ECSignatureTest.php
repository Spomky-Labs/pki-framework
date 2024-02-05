<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\Signature;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\CryptoTypes\Signature\ECSignature;

/**
 * @internal
 */
final class ECSignatureTest extends TestCase
{
    #[Test]
    public function create(): ECSignature
    {
        $sig = ECSignature::create('123456789', '987654321');
        static::assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    #[Test]
    #[Depends('create')]
    public function encode(ECSignature $sig): void
    {
        $el = $sig->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
    }

    #[Test]
    #[Depends('create')]
    public function toDER(ECSignature $sig): string
    {
        $der = $sig->toDER();
        static::assertIsString($der);
        return $der;
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('toDER')]
    public function decode($data): ECSignature
    {
        $sig = ECSignature::fromDER($data);
        static::assertInstanceOf(ECSignature::class, $sig);
        return $sig;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(ECSignature $ref, ECSignature $sig): void
    {
        static::assertEquals($ref, $sig);
    }

    #[Test]
    #[Depends('create')]
    public function rValue(ECSignature $sig): void
    {
        static::assertSame('123456789', $sig->r());
    }

    #[Test]
    #[Depends('create')]
    public function sValue(ECSignature $sig): void
    {
        static::assertSame('987654321', $sig->s());
    }

    #[Test]
    #[Depends('create')]
    public function bitString(ECSignature $sig): void
    {
        static::assertInstanceOf(BitString::class, $sig->bitString());
    }
}
