<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;

/**
 * @internal
 */
final class GenericAlgorithmIdentifierTest extends TestCase
{
    #[Test]
    public function create(): GenericAlgorithmIdentifier
    {
        $ai = GenericAlgorithmIdentifier::create('1.3.6.1.3', UnspecifiedType::create(Integer::create(42)));
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    #[Test]
    #[Depends('create')]
    public function verifyName(?GenericAlgorithmIdentifier $ai = null): void
    {
        static::assertSame('1.3.6.1.3', $ai->name());
    }

    #[Test]
    #[Depends('create')]
    public function parameters(GenericAlgorithmIdentifier $ai): void
    {
        static::assertInstanceOf(UnspecifiedType::class, $ai->parameters());
    }

    #[Test]
    #[Depends('create')]
    public function encode(GenericAlgorithmIdentifier $ai): void
    {
        static::assertInstanceOf(Sequence::class, $ai->toASN1());
    }
}
