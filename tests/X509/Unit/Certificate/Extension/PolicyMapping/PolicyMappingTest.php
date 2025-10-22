<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\PolicyMapping;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappings\PolicyMapping;

/**
 * @internal
 */
final class PolicyMappingTest extends TestCase
{
    public const ISSUER_POLICY = '1.3.6.1.3.1';

    public const SUBJECT_POLICY = '1.3.6.1.3.2';

    #[Test]
    public function create(): PolicyMapping
    {
        $mapping = PolicyMapping::create(self::ISSUER_POLICY, self::SUBJECT_POLICY);
        static::assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    #[Test]
    #[Depends('create')]
    public function encode(PolicyMapping $mapping): string
    {
        $el = $mapping->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): PolicyMapping
    {
        $mapping = PolicyMapping::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(PolicyMapping $ref, PolicyMapping $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function issuerDomainPolicy(PolicyMapping $mapping)
    {
        static::assertSame(self::ISSUER_POLICY, $mapping->issuerDomainPolicy());
    }

    #[Test]
    #[Depends('create')]
    public function subjectDomainPolicy(PolicyMapping $mapping)
    {
        static::assertSame(self::SUBJECT_POLICY, $mapping->subjectDomainPolicy());
    }
}
