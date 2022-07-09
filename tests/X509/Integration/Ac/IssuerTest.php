<?php

declare(strict_types=1);

namespace Sop\Test\X509\Integration\Ac;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X501\ASN1\Name;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\Certificate\Certificate;

/**
 * @internal
 */
final class IssuerTest extends TestCase
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

    public function testIdentifiesPKC()
    {
        $iss = AttCertIssuer::fromPKC(self::$_pkc);
        $this->assertTrue($iss->identifiesPKC(self::$_pkc));
    }

    public function testIdentifiesPKCMismatch()
    {
        $iss = AttCertIssuer::fromName(Name::fromString('cn=Fail'));
        $this->assertFalse($iss->identifiesPKC(self::$_pkc));
    }
}
