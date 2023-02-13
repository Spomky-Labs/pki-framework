<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Ac;

use PHPUnit\Framework\Attributes\Test;
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
    private static ?Certificate $_pkc = null;

    public static function setUpBeforeClass(): void
    {
        self::$_pkc = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pkc = null;
    }

    #[Test]
    public function identifiesPKCSimple()
    {
        $holder = Holder::fromPKC(self::$_pkc);
        static::assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    #[Test]
    public function identifiesPKCByEntityName()
    {
        $gn = GeneralNames::create(DirectoryName::create(self::$_pkc->tbsCertificate()->subject()));
        $holder = Holder::create(null, $gn);
        static::assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    #[Test]
    public function identifiesPKCByEntityNameSANDirectoryName()
    {
        $gn = GeneralNames::create(DirectoryName::fromDNString('o=ACME Alternative Ltd., c=FI, cn=alt.example.com'));
        $holder = Holder::create(null, $gn);
        static::assertTrue($holder->identifiesPKC(self::$_pkc));
    }

    #[Test]
    public function identifiesPKCNoIdentifiers()
    {
        $holder = Holder::create();
        static::assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    #[Test]
    public function identifiesPKCNoCertIdMatch()
    {
        $is = IssuerSerial::create(GeneralNames::create(DirectoryName::fromDNString('cn=Fail')), '1');
        $holder = Holder::create($is);
        static::assertFalse($holder->identifiesPKC(self::$_pkc));
    }

    #[Test]
    public function identifiesPKCNoEntityNameMatch()
    {
        $gn = GeneralNames::create(DirectoryName::fromDNString('cn=Fail'));
        $holder = Holder::create(null, $gn);
        static::assertFalse($holder->identifiesPKC(self::$_pkc));
    }
}
