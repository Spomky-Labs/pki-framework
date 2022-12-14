<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Ac;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * @internal
 */
final class IssuerTest extends TestCase
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
    public function identifiesPKC()
    {
        $iss = AttCertIssuer::fromPKC(self::$_pkc);
        static::assertTrue($iss->identifiesPKC(self::$_pkc));
    }

    #[Test]
    public function identifiesPKCMismatch()
    {
        $iss = AttCertIssuer::fromName(Name::fromString('cn=Fail'));
        static::assertFalse($iss->identifiesPKC(self::$_pkc));
    }
}
