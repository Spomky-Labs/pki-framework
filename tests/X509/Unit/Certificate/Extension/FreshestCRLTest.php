<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate\Extension;

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
    private static $_dp;

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

    /**
     * @test
     */
    public function create()
    {
        $ext = FreshestCRLExtension::create(false, self::$_dp);
        static::assertInstanceOf(FreshestCRLExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function oID(Extension $ext)
    {
        static::assertEquals(Extension::OID_FRESHEST_CRL, $ext->oid());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function critical(Extension $ext)
    {
        static::assertFalse($ext->isCritical());
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
        $ext = FreshestCRLExtension::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(FreshestCRLExtension::class, $ext);
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
}
