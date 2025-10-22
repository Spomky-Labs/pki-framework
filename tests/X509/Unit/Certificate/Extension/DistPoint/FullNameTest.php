<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\DistPoint;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitTagging;
use SpomkyLabs\Pki\ASN1\Type\TaggedType;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\FullName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class FullNameTest extends TestCase
{
    public const URI = 'urn:test';

    #[Test]
    public function create(): FullName
    {
        $name = FullName::fromURI(self::URI);
        static::assertInstanceOf(FullName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    public function encode(FullName $name): string
    {
        $el = $name->toASN1();
        static::assertInstanceOf(ImplicitTagging::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): FullName
    {
        $name = FullName::fromTaggedType(TaggedType::fromDER($data));
        static::assertInstanceOf(FullName::class, $name);
        return $name;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(FullName $ref, FullName $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function names(FullName $name)
    {
        $names = $name->names();
        static::assertInstanceOf(GeneralNames::class, $names);
    }
}
