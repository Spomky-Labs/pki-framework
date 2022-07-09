<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\Ac;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\Certificate\Certificate;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

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
        $this->assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCByEntityName()
    {
        $gn = new GeneralNames(new DirectoryName(self::$_pkc->tbsCertificate()->subject()));
        $holder = new Holder(null, $gn);
        $this->assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCByEntityNameSANDirectoryName()
    {
        $gn = new GeneralNames(DirectoryName::fromDNString('o=ACME Alternative Ltd., c=FI, cn=alt.example.com'));
        $holder = new Holder(null, $gn);
        $this->assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCNoIdentifiers()
    {
        $holder = new Holder();
        $this->assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCNoCertIdMatch()
    {
        $is = new IssuerSerial(new GeneralNames(DirectoryName::fromDNString('cn=Fail')), 1);
        $holder = new Holder($is);
        $this->assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    /**
     * @test
     */
    public function identifiesPKCNoEntityNameMatch()
    {
        $gn = new GeneralNames(DirectoryName::fromDNString('cn=Fail'));
        $holder = new Holder(null, $gn);
        $this->assertFalse($holder->identifiesPKC(self::$_pkc));
    }
}
