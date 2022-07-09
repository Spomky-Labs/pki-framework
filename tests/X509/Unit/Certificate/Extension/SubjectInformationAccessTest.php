<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AccessDescription\SubjectAccessDescription;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\SubjectInformationAccessExtension;
use Sop\X509\GeneralName\UniformResourceIdentifier;

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
        $this->assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_SUBJECT_INFORMATION_ACCESS, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        $this->assertFalse($ext->isCritical());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
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
        $this->assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function accessDescriptions(SubjectInformationAccessExtension $ext)
    {
        $this->assertContainsOnlyInstancesOf(SubjectAccessDescription::class, $ext->accessDescriptions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(SubjectInformationAccessExtension $ext)
    {
        $this->assertCount(2, $ext);
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
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(SubjectAccessDescription::class, $values);
    }
}
