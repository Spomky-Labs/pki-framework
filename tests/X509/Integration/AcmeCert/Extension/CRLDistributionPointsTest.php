<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\CRLDistributionPointsExtension;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use Sop\X509\Certificate\Extension\DistributionPoint\FullName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class CRLDistributionPointsTest extends RefExtTestHelper
{
    /**
     * @return CRLDistributionPointsExtension
     *
     * @test
     */
    public function cRLDistributionPointsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_CRL_DISTRIBUTION_POINTS);
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends cRLDistributionPointsExtension
     *
     * @return DistributionPoint
     *
     * @test
     */
    public function distributionPoint(CRLDistributionPointsExtension $ext)
    {
        $cdp = $ext->getIterator()[0];
        static::assertInstanceOf(DistributionPoint::class, $cdp);
        return $cdp;
    }

    /**
     * @depends distributionPoint
     *
     * @return FullName
     *
     * @test
     */
    public function fullName(DistributionPoint $dp)
    {
        $name = $dp->distributionPointName();
        static::assertEquals(DistributionPointName::TAG_FULL_NAME, $name->tag());
        return $name;
    }

    /**
     * @depends fullName
     *
     * @test
     */
    public function uRI(FullName $name)
    {
        $uri = $name->names()
            ->firstOf(GeneralName::TAG_URI)
            ->uri();
        static::assertEquals('http://example.com/myca.crl', $uri);
    }

    /**
     * @depends distributionPoint
     *
     * @return ReasonFlags
     *
     * @test
     */
    public function reasons(DistributionPoint $dp)
    {
        $reasons = $dp->reasons();
        static::assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends reasons
     *
     * @test
     */
    public function reasonFlags(ReasonFlags $reasons)
    {
        static::assertTrue($reasons->isKeyCompromise());
        static::assertTrue($reasons->isCACompromise());
        static::assertFalse($reasons->isAffiliationChanged());
        static::assertFalse($reasons->isSuperseded());
        static::assertFalse($reasons->isCessationOfOperation());
        static::assertFalse($reasons->isCertificateHold());
        static::assertFalse($reasons->isPrivilegeWithdrawn());
        static::assertFalse($reasons->isAACompromise());
    }

    /**
     * @depends distributionPoint
     *
     * @return GeneralNames
     *
     * @test
     */
    public function issuer(DistributionPoint $dp)
    {
        $issuer = $dp->crlIssuer();
        static::assertInstanceOf(GeneralNames::class, $issuer);
        return $issuer;
    }

    /**
     * @depends issuer
     *
     * @test
     */
    public function issuerDirName(GeneralNames $gn)
    {
        $dn = $gn->firstOf(GeneralName::TAG_DIRECTORY_NAME)->dn();
        static::assertEquals('cn=ACME,o=ACME Ltd.', $dn->toString());
    }
}
