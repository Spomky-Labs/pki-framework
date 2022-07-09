<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\X509\Certificate\Extension\CRLDistributionPointsExtension;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class CRLDistributionPointTest extends TestCase
{
    final public const DP_URI = 'urn:test';

    final public const ISSUER_DN = 'cn=Issuer';

    /**
     * @test
     */
    public function createDistributionPoint()
    {
        $name = new FullName(new GeneralNames(new UniformResourceIdentifier(self::DP_URI)));
        $reasons = new ReasonFlags(ReasonFlags::PRIVILEGE_WITHDRAWN);
        $issuer = new GeneralNames(DirectoryName::fromDNString(self::ISSUER_DN));
        $dp = new DistributionPoint($name, $reasons, $issuer);
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends createDistributionPoint
     *
     * @test
     */
    public function create(DistributionPoint $dp)
    {
        $ext = new CRLDistributionPointsExtension(true, $dp, new DistributionPoint());
        $this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_CRL_DISTRIBUTION_POINTS, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
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
        $ext = CRLDistributionPointsExtension::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
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
    public function countMethod(CRLDistributionPointsExtension $ext)
    {
        $this->assertCount(2, $ext);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(CRLDistributionPointsExtension $ext)
    {
        $values = [];
        foreach ($ext as $dp) {
            $values[] = $dp;
        }
        $this->assertCount(2, $values);
        $this->assertContainsOnlyInstancesOf(DistributionPoint::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function distributionPoint(CRLDistributionPointsExtension $ext)
    {
        $dp = $ext->distributionPoints()[0];
        $this->assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends distributionPoint
     *
     * @test
     */
    public function dPName(DistributionPoint $dp)
    {
        $uri = $dp->fullName()
            ->names()
            ->firstURI();
        $this->assertEquals(self::DP_URI, $uri);
    }

    /**
     * @depends distributionPoint
     *
     * @test
     */
    public function dPReasons(DistributionPoint $dp)
    {
        $this->assertTrue($dp->reasons() ->isPrivilegeWithdrawn());
    }

    /**
     * @depends distributionPoint
     *
     * @test
     */
    public function dPIssuer(DistributionPoint $dp)
    {
        $this->assertEquals(self::ISSUER_DN, $dp->crlIssuer() ->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(CRLDistributionPointsExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasCRLDistributionPoints());
        return $extensions;
    }

    /**
     * @depends extensions
     *
     * @test
     */
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->crlDistributionPoints();
        $this->assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $ext = new CRLDistributionPointsExtension(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    /**
     * @test
     */
    public function decodeEmptyFail()
    {
        $seq = new Sequence();
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_CRL_DISTRIBUTION_POINTS),
            new OctetString($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        CRLDistributionPointsExtension::fromASN1($ext_seq);
    }
}
