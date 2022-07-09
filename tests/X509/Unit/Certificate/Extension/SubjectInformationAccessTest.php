<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectInformationAccessExtension;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class SubjectInformationAccessTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $ext = new SubjectInformationAccessExtension(
            false,
            new SubjectAccessDescription(
                SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
                new UniformResourceIdentifier('urn:test')
            ),
            new SubjectAccessDescription(
                SubjectAccessDescription::OID_METHOD_TIME_STAMPING,
                new UniformResourceIdentifier('https://ts.example.com/')
            )
        );
        static::assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_SUBJECT_INFORMATION_ACCESS, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertFalse($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $ext = SubjectInformationAccessExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function accessDescriptions(SubjectInformationAccessExtension $ext)
    {
        static::assertContainsOnlyInstancesOf(SubjectAccessDescription::class, $ext->accessDescriptions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(SubjectInformationAccessExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(SubjectInformationAccessExtension $ext)
    {
        $values = [];
        foreach ($ext as $desc) {
            $values[] = $desc;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(SubjectAccessDescription::class, $values);
    }
}
