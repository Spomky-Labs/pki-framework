<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Ac;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class HolderTest extends TestCase
{
    private static $_pkc;

    public static function setUpBeforeClass(): void
    {
        self::$_pkc = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pkc = null;
    }

    /**
     * @test
     */
    public function identifiesPKCSimple()
    {
        $holder = Holder::fromPKC(self::$_pkc);
        static::assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCByEntityName()
    {
        $gn = new GeneralNames(new DirectoryName(self::$_pkc->tbsCertificate()->subject()));
        $holder = new Holder(null, $gn);
        static::assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCByEntityNameSANDirectoryName()
    {
        $gn = new GeneralNames(DirectoryName::fromDNString('o=ACME Alternative Ltd., c=FI, cn=alt.example.com'));
        $holder = new Holder(null, $gn);
        static::assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCNoIdentifiers()
    {
        $holder = new Holder();
        static::assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCNoCertIdMatch()
    {
        $is = new IssuerSerial(new GeneralNames(DirectoryName::fromDNString('cn=Fail')), 1);
        $holder = new Holder($is);
        static::assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCNoEntityNameMatch()
    {
        $gn = new GeneralNames(DirectoryName::fromDNString('cn=Fail'));
        $holder = new Holder(null, $gn);
        static::assertFalse($holder->identifiesPKC(self::$_pkc));
    }
}
