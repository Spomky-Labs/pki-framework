<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCert\Extension;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

abstract class RefExtTestHelper extends TestCase
{
    protected static $_extensions;

    public static function setUpBeforeClass(): void
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        $cert = Certificate::fromPEM($pem);
        self::$_extensions = $cert->tbsCertificate()->extensions();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_extensions = null;
    }
}
