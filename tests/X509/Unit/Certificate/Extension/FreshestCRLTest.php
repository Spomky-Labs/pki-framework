<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\FreshestCRLExtension;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class FreshestCRLTest extends TestCase
{
    private static $_dp;

    public static function setUpBeforeClass(): void
    {
        $name = new FullName(new GeneralNames(new UniformResourceIdentifier('urn:test')));
        $reasons = new ReasonFlags(ReasonFlags::PRIVILEGE_WITHDRAWN);
        $issuer = new GeneralNames(DirectoryName::fromDNString('cn=Issuer'));
        self::$_dp = new DistributionPoint($name, $reasons, $issuer);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_dp = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $ext = new FreshestCRLExtension(false, self::$_dp);
        $this->assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_FRESHEST_CRL, $ext->oid());
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
        $ext = FreshestCRLExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(FreshestCRLExtension::class, $ext);
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
}
