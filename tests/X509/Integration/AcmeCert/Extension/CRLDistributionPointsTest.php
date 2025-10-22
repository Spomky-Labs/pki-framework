<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\X509\Certificate\Extension\CRLDistributionPointsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPointName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\FullName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class CRLDistributionPointsTest extends RefExtTestHelper
{
    #[Test]
    public function cRLDistributionPointsExtension(): CRLDistributionPointsExtension
    {
        $ext = self::$_extensions->get(Extension::OID_CRL_DISTRIBUTION_POINTS);
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('cRLDistributionPointsExtension')]
    public function distributionPoint(CRLDistributionPointsExtension $ext): DistributionPoint
    {
        $cdp = $ext->getIterator()[0];
        static::assertInstanceOf(DistributionPoint::class, $cdp);
        return $cdp;
    }

    /**
     * @return FullName
     */
    #[Test]
    #[Depends('distributionPoint')]
    public function fullName(DistributionPoint $dp): DistributionPointName
    {
        $name = $dp->distributionPointName();
        static::assertSame(DistributionPointName::TAG_FULL_NAME, $name->tag());
        return $name;
    }

    #[Test]
    #[Depends('fullName')]
    public function uRI(FullName $name)
    {
        $uri = $name->names()
            ->firstOf(GeneralName::TAG_URI)
            ->uri();
        static::assertSame('http://example.com/myca.crl', $uri);
    }

    /**
     * @return ReasonFlags
     */
    #[Test]
    #[Depends('distributionPoint')]
    public function reasons(DistributionPoint $dp)
    {
        $reasons = $dp->reasons();
        static::assertInstanceOf(ReasonFlags::class, $reasons);
        return $reasons;
    }

    #[Test]
    #[Depends('reasons')]
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
     * @return GeneralNames
     */
    #[Test]
    #[Depends('distributionPoint')]
    public function issuer(DistributionPoint $dp)
    {
        $issuer = $dp->crlIssuer();
        static::assertInstanceOf(GeneralNames::class, $issuer);
        return $issuer;
    }

    #[Test]
    #[Depends('issuer')]
    public function issuerDirName(GeneralNames $gn)
    {
        $dn = $gn->firstOf(GeneralName::TAG_DIRECTORY_NAME)->dn();
        static::assertSame('cn=ACME,o=ACME Ltd.', $dn->toString());
    }
}
