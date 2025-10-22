<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function create(): SubjectInformationAccessExtension
    {
        $ext = SubjectInformationAccessExtension::create(
            false,
            SubjectAccessDescription::create(
                SubjectAccessDescription::OID_METHOD_CA_REPOSITORY,
                UniformResourceIdentifier::create('urn:test')
            ),
            SubjectAccessDescription::create(
                SubjectAccessDescription::OID_METHOD_TIME_STAMPING,
                UniformResourceIdentifier::create('https://ts.example.com/')
            )
        );
        static::assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_SUBJECT_INFORMATION_ACCESS, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertFalse($ext->isCritical());
    }

    #[Test]
    #[Depends('create')]
    public function encode(Extension $ext)
    {
        $seq = $ext->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der)
    {
        $ext = SubjectInformationAccessExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(SubjectInformationAccessExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function accessDescriptions(SubjectInformationAccessExtension $ext)
    {
        static::assertContainsOnlyInstancesOf(SubjectAccessDescription::class, $ext->accessDescriptions());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(SubjectInformationAccessExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
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
