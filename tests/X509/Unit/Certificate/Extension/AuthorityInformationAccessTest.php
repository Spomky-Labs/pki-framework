<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

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
    /**
     * @test
     */
    public function create()
    {
        $ext = new AuthorityInformationAccessExtension(
            false,
            new AuthorityAccessDescription(
                AuthorityAccessDescription::OID_METHOD_CA_ISSUERS,
                new UniformResourceIdentifier('urn:test')
            ),
            new AuthorityAccessDescription(
                AuthorityAccessDescription::OID_METHOD_OSCP,
                new UniformResourceIdentifier('https://oscp.example.com/')
            )
        );
        static::assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_AUTHORITY_INFORMATION_ACCESS, $ext->oid());
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
        $ext = AuthorityInformationAccessExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
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
    public function accessDescriptions(AuthorityInformationAccessExtension $ext)
    {
        static::assertContainsOnlyInstancesOf(AuthorityAccessDescription::class, $ext->accessDescriptions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(AuthorityInformationAccessExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
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
