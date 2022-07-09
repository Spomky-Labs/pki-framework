<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\PolicyMapping;

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

    /**
     * @test
     */
    public function create()
    {
        $mapping = new PolicyMapping(self::ISSUER_POLICY, self::SUBJECT_POLICY);
        static::assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(PolicyMapping $mapping)
    {
        $el = $mapping->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $mapping = PolicyMapping::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(PolicyMapping::class, $mapping);
        return $mapping;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(PolicyMapping $ref, PolicyMapping $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function issuerDomainPolicy(PolicyMapping $mapping)
    {
        static::assertEquals(self::ISSUER_POLICY, $mapping->issuerDomainPolicy());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function subjectDomainPolicy(PolicyMapping $mapping)
    {
        static::assertEquals(self::SUBJECT_POLICY, $mapping->subjectDomainPolicy());
    }
}
