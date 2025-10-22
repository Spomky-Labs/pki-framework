<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\AccessDescription;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class SubjectAccessDescriptionTest extends TestCase
{
    public const URI = 'urn:test';

    #[Test]
    public function create(): SubjectAccessDescription
    {
        $desc = SubjectAccessDescription::create(
            SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
            UniformResourceIdentifier::create(self::URI)
        );
        static::assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }

    #[Test]
    #[Depends('create')]
    public function encode(SubjectAccessDescription $desc): string
    {
        $el = $desc->toASN1();
        static::assertInstanceOf(Sequence::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): SubjectAccessDescription
    {
        $desc = SubjectAccessDescription::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(SubjectAccessDescription $ref, SubjectAccessDescription $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function isCARepository(SubjectAccessDescription $desc)
    {
        static::assertTrue($desc->isCARepositoryMethod());
    }

    #[Test]
    #[Depends('create')]
    public function isNotTimeStamping(SubjectAccessDescription $desc)
    {
        static::assertFalse($desc->isTimeStampingMethod());
    }

    #[Test]
    #[Depends('create')]
    public function accessMethod(SubjectAccessDescription $desc)
    {
        static::assertSame(SubjectAccessDescription::OID_METHOD_CA_REPOSITORY, $desc->accessMethod());
    }

    #[Test]
    #[Depends('create')]
    public function location(SubjectAccessDescription $desc)
    {
        static::assertSame(self::URI, $desc->accessLocation()->string());
    }
}
