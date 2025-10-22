<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidator;

/**
 * @internal
 */
final class CertificationPathValidationTest extends TestCase
{
    private static ?CertificationPath $_path;

    public static function setUpBeforeClass(): void
    {
        $certs = [
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem')),
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-ecdsa.pem')),
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem')),
        ];
        self::$_path = CertificationPath::create(...$certs);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_path = null;
    }

    #[Test]
    public function validateDefault(): PathValidationResult
    {
        $result = self::$_path->validate(PathValidationConfig::defaultConfig());
        static::assertInstanceOf(PathValidationResult::class, $result);
        return $result;
    }

    #[Test]
    #[Depends('validateDefault')]
    public function verifyResult(?PathValidationResult $result = null)
    {
        $expected_cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        static::assertEquals($expected_cert, $result->certificate());
    }

    #[Test]
    public function validateExpired()
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(new DateTimeImmutable('2026-01-03'));
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    #[Test]
    public function validateNotBeforeFail()
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(new DateTimeImmutable('2015-12-31'));
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    #[Test]
    public function validatePathLengthFail()
    {
        $config = PathValidationConfig::defaultConfig()->withMaxLength(0);
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    #[Test]
    public function noCertsFail()
    {
        $this->expectException(LogicException::class);
        PathValidator::create(Crypto::getDefault(), PathValidationConfig::defaultConfig());
    }

    #[Test]
    public function explicitTrustAnchor()
    {
        $config = PathValidationConfig::defaultConfig()->withTrustAnchor(self::$_path->certificates()[0]);
        $validator = PathValidator::create(Crypto::getDefault(), $config, ...self::$_path->certificates());
        static::assertInstanceOf(PathValidationResult::class, $validator->validate());
    }
}
