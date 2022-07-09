<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\RelativeName;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\FreshestCRLExtension;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

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
        static::assertInstanceOf(FreshestCRLExtension::class, $ext);
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
        static::assertInstanceOf(DistributionPoint::class, $cdp);
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
        static::assertEquals(DistributionPointName::TAG_RDN, $name->tag());
        return $name;
    }

    /**
     * @depends relativeName
     *
     * @test
     */
    public function rDN(RelativeName $name)
    {
        static::assertEquals('cn=Delta Distribution Point', $name->rdn() ->toString());
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
