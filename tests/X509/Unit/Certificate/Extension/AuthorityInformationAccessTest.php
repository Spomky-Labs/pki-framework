<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityInformationAccessExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class AuthorityInformationAccessTest extends TestCase
{
    #[Test]
    public function create(): AuthorityInformationAccessExtension
    {
        $ext = AuthorityInformationAccessExtension::create(
            false,
            AuthorityAccessDescription::create(
                AuthorityAccessDescription::OID_METHOD_CA_ISSUERS,
                UniformResourceIdentifier::create('urn:test')
            ),
            AuthorityAccessDescription::create(
                AuthorityAccessDescription::OID_METHOD_OSCP,
                UniformResourceIdentifier::create('https://oscp.example.com/')
            )
        );
        static::assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_AUTHORITY_INFORMATION_ACCESS, $ext->oid());
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
        $ext = AuthorityInformationAccessExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
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
    public function accessDescriptions(AuthorityInformationAccessExtension $ext)
    {
        static::assertContainsOnlyInstancesOf(AuthorityAccessDescription::class, $ext->accessDescriptions());
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(AuthorityInformationAccessExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(AuthorityInformationAccessExtension $ext)
    {
        $values = [];
        foreach ($ext as $desc) {
            $values[] = $desc;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(AuthorityAccessDescription::class, $values);
    }
}
