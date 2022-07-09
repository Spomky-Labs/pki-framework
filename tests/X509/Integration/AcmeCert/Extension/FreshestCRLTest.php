<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\AcmeCert\Extension;

use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use Sop\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use Sop\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use Sop\X509\Certificate\Extension\DistributionPoint\RelativeName;
use Sop\X509\Certificate\Extension\Extension;
use Sop\X509\Certificate\Extension\FreshestCRLExtension;
use Sop\X509\GeneralName\GeneralName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class FreshestCRLTest extends RefExtTestHelper
{
    /**
     * @return FreshestCRLExtension
     *
     * @test
     */
    public function freshestCRLExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_FRESHEST_CRL);
        $this->assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends freshestCRLExtension
     *
     * @return DistributionPoint
     *
     * @test
     */
    public function distributionPoint(FreshestCRLExtension $ext)
    {
        $cdp = $ext->getIterator()[0];
        $this->assertInstanceOf(DistributionPoint::class, $cdp);
        return $cdp;
    }

    /**
     * @depends distributionPoint
     *
     * @return RelativeName
     *
     * @test
     */
    public function relativeName(DistributionPoint $dp)
    {
        $name = $dp->distributionPointName();
        $this->assertEquals(DistributionPointName::TAG_RDN, $name->tag());
        return $name;
    }

    /**
     * @depends relativeName
     *
     * @test
     */
    public function rDN(RelativeName $name)
    {
        $this->assertEquals('cn=Delta Distribution Point', $name->rdn() ->toString());
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
        $this->assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    /**
     * @depends reasons
     *
     * @test
     */
    public function reasonFlags(ReasonFlags $reasons)
    {
        $this->assertTrue($reasons->isKeyCompromise());
        $this->assertTrue($reasons->isCACompromise());
        $this->assertFalse($reasons->isAffiliationChanged());
        $this->assertFalse($reasons->isSuperseded());
        $this->assertFalse($reasons->isCessationOfOperation());
        $this->assertFalse($reasons->isCertificateHold());
        $this->assertFalse($reasons->isPrivilegeWithdrawn());
        $this->assertFalse($reasons->isAACompromise());
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
        $this->assertInstanceOf(GeneralNames::class, $issuer);
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
        $this->assertEquals('cn=ACME,o=ACME Ltd.', $dn->toString());
    }
}
