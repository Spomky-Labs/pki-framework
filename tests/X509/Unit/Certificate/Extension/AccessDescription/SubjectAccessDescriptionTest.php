<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension\AccessDescription;

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

    /**
     * @test
     */
    public function create()
    {
        $desc = SubjectAccessDescription::create(
            SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
            UniformResourceIdentifier::create(self::URI)
        );
        static::assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(SubjectAccessDescription $desc)
    {
        $el = $desc->toASN1();
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
        $desc = SubjectAccessDescription::fromASN1(Sequence::fromDER($data));
        static::assertInstanceOf(SubjectAccessDescription::class, $desc);
        return $desc;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(SubjectAccessDescription $ref, SubjectAccessDescription $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isCARepository(SubjectAccessDescription $desc)
    {
        static::assertTrue($desc->isCARepositoryMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function isNotTimeStamping(SubjectAccessDescription $desc)
    {
        static::assertFalse($desc->isTimeStampingMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function accessMethod(SubjectAccessDescription $desc)
    {
        static::assertEquals(SubjectAccessDescription::OID_METHOD_CA_REPOSITORY, $desc->accessMethod());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function location(SubjectAccessDescription $desc)
    {
        static::assertEquals(self::URI, $desc->accessLocation()->string());
    }
}
