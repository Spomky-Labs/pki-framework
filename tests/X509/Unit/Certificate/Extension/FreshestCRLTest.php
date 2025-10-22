<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\DistributionPoint;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\FullName;
use SpomkyLabs\Pki\X509\Certificate\Extension\DistributionPoint\ReasonFlags;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\FreshestCRLExtension;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * @internal
 */
final class FreshestCRLTest extends TestCase
{
    private static ?DistributionPoint $_dp = null;

    public static function setUpBeforeClass(): void
    {
        $name = FullName::create(GeneralNames::create(UniformResourceIdentifier::create('urn:test')));
        $reasons = ReasonFlags::create(ReasonFlags::PRIVILEGE_WITHDRAWN);
        $issuer = GeneralNames::create(DirectoryName::fromDNString('cn=Issuer'));
        self::$_dp = DistributionPoint::create($name, $reasons, $issuer);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_dp = null;
    }

    #[Test]
    public function create(): FreshestCRLExtension
    {
        $ext = FreshestCRLExtension::create(false, self::$_dp);
        static::assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    public function oID(Extension $ext)
    {
        static::assertSame(Extension::OID_FRESHEST_CRL, $ext->oid());
    }

    #[Test]
    #[Depends('create')]
    public function critical(Extension $ext)
    {
        static::assertFalse($ext->isCritical());
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
        $ext = FreshestCRLExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(Extension $ref, Extension $new)
    {
        static::assertEquals($ref, $new);
    }
}
