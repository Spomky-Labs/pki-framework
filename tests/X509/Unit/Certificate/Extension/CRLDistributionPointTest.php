<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
    public function createDistributionPoint(): DistributionPoint
    {
        $name = FullName::create(GeneralNames::create(UniformResourceIdentifier::create(self::DP_URI)));
        $reasons = ReasonFlags::create(ReasonFlags::PRIVILEGE_WITHDRAWN);
        $issuer = GeneralNames::create(DirectoryName::fromDNString(self::ISSUER_DN));
        $dp = DistributionPoint::create($name, $reasons, $issuer);
        static::assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    #[Test]
    #[Depends('createDistributionPoint')]
    public function create(DistributionPoint $dp): CRLDistributionPointsExtension
    {
        $ext = CRLDistributionPointsExtension::create(true, $dp, DistributionPoint::create());
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_CRL_DISTRIBUTION_POINTS, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertTrue($ext->isCritical());
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
        $ext = CRLDistributionPointsExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
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
    public function countMethod(CRLDistributionPointsExtension $ext)
    {
        static::assertCount(2, $ext);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(CRLDistributionPointsExtension $ext)
    {
        $values = [];
        foreach ($ext as $dp) {
            $values[] = $dp;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(DistributionPoint::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function distributionPoint(CRLDistributionPointsExtension $ext)
    {
        $dp = $ext->distributionPoints()[0];
        static::assertInstanceOf(DistributionPoint::class, $dp);
        return $dp;
    }

    #[Test]
    #[Depends('distributionPoint')]
    public function dPName(DistributionPoint $dp)
    {
        $uri = $dp->fullName()
            ->names()
            ->firstURI();
        static::assertSame(self::DP_URI, $uri);
    }

    #[Test]
    #[Depends('distributionPoint')]
    public function dPReasons(DistributionPoint $dp)
    {
        static::assertTrue($dp->reasons()->isPrivilegeWithdrawn());
    }

    #[Test]
    #[Depends('distributionPoint')]
    public function dPIssuer(DistributionPoint $dp)
    {
        static::assertSame(self::ISSUER_DN, $dp->crlIssuer()->firstDN()->toString());
    }

    #[Test]
    #[Depends('create')]
    public function extensions(CRLDistributionPointsExtension $ext)
    {
        $extensions = Extensions::create($ext);
        static::assertTrue($extensions->hasCRLDistributionPoints());
        return $extensions;
    }

    #[Test]
    #[Depends('extensions')]
    public function fromExtensions(Extensions $exts)
    {
        $ext = $exts->crlDistributionPoints();
        static::assertInstanceOf(CRLDistributionPointsExtension::class, $ext);
    }

    #[Test]
    public function encodeEmptyFail()
    {
        $ext = CRLDistributionPointsExtension::create(false);
        $this->expectException(LogicException::class);
        $ext->toASN1();
    }

    #[Test]
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
