<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\AccessDescription\AuthorityAccessDescription;
use Sop\X509\Certificate\Extension\AuthorityInformationAccessExtension;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\GeneralName\UniformResourceIdentifier;

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
        $this->assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_AUTHORITY_INFORMATION_ACCESS, $ext->oid());
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
        $ext = AuthorityInformationAccessExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AuthorityInformationAccessExtension::class, $ext);
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
    public function accessDescriptions(AuthorityInformationAccessExtension $ext)
    {
        $this->assertContainsOnlyInstancesOf(AuthorityAccessDescription::class, $ext->accessDescriptions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(AuthorityInformationAccessExtension $ext)
    {
        $this->assertCount(2, $ext);
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
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(AuthorityAccessDescription::class, $values);
    }
}
