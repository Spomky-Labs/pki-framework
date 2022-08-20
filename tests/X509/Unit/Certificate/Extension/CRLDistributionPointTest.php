<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\X509\Certificate\Extension\CRLDistributionPointsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\FullName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
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
        $name = new FullName(GeneralNames::create(UniformResourceIdentifier::create(self::DP_URI)));
        $reasons = new ReasonFlags(ReasonFlags::PRIVILEGE_WITHDRAWN);
        $issuer = GeneralNames::create(DirectoryName::fromDNString(self::ISSUER_DN));
        $dp = new DistributionPoint($name, $reasons, $issuer);
        static::assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    /**
     * @depends createDistributionPoint
     *
     * @test
     */
    public function create(DistributionPoint $dp)
    {
        $ext = CRLDistributionPointsExtension::create(true, $dp, new DistributionPoint());
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_CRL_DISTRIBUTION_POINTS, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
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
        $ext = CRLDistributionPointsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
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
    public function countMethod(CRLDistributionPointsExtension $ext)
    {
        static::assertCount(2, $ext);
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
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(DistributionPoint::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function distributionPoint(CRLDistributionPointsExtension $ext)
    {
        $dp = $ext->distributionPoints()[0];
        static::assertInstanceOf(DistributionPoint::class, $dp);
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
        static::assertEquals(self::DP_URI, $uri);
    }

    /**
     * @depends distributionPoint
     *
     * @test
     */
    public function dPReasons(DistributionPoint $dp)
    {
        static::assertTrue($dp->reasons()->isPrivilegeWithdrawn());
    }

    /**
     * @depends distributionPoint
     *
     * @test
     */
    public function dPIssuer(DistributionPoint $dp)
    {
        static::assertEquals(self::ISSUER_DN, $dp->crlIssuer()->firstDN());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function extensions(CRLDistributionPointsExtension $ext)
    {
        $extensions = new Extensions($ext);
        static::assertTrue($extensions->hasCRLDistributionPoints());
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
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
    }

    /**
     * @test
     */
    public function encodeEmptyFail()
    {
        $ext = CRLDistributionPointsExtension::create(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    /**
     * @test
     */
    public function decodeEmptyFail()
    {
        $seq = Sequence::create();
        $ext_seq = Sequence::create(
            ObjectIdentifier::create(Extension::OID_CRL_DISTRIBUTION_POINTS),
            OctetString::create($seq->toDER())
        );
        $this->expectException(UnexpectedValueException::class);
        CRLDistributionPointsExtension::fromASN1($ext_seq);
    }
}
