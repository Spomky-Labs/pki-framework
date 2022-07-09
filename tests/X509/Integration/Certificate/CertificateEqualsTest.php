<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Certificate;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * @internal
 */
final class CertificateEqualsTest extends TestCase
{
    private static $_cert1;

    private static $_cert1DifKey;

    private static $_cert2;

    public static function setUpBeforeClass(): void
    {
        self::$_cert1 = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $pubkey = PublicKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $tbs = self::$_cert1->tbsCertificate()->withSubjectPublicKeyInfo($pubkey);
        $privkey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
        self::$_cert1DifKey = $tbs->sign(self::$_cert1->signatureAlgorithm(), $privkey);
        self::$_cert2 = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_cert1 = null;
        self::$_cert1DifKey = null;
        self::$_cert2 = null;
    }

    /**
     * @test
     */
    public function equals()
    {
        static::assertTrue(self::$_cert1->equals(self::$_cert1));
    }

    /**
     * @test
     */
    public function notEquals()
    {
        static::assertFalse(self::$_cert1->equals(self::$_cert2));
    }

    /**
     * @test
     */
    public function differentPubKeyNotEquals()
    {
        static::assertFalse(self::$_cert1->equals(self::$_cert1DifKey));
    }
}
