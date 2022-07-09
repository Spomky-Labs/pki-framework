<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\Exception\PathValidationException;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;
use Sop\X509\CertificationPath\PathValidation\PathValidator;

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
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem')), ];
        self::$_path = new CertificationPath(...$certs);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_path = null;
    }

    /**
     * @return PathValidationResult
     *
     * @test
     */
    public function validateDefault()
    {
        $result = self::$_path->validate(PathValidationConfig::defaultConfig());
        static::assertInstanceOf(PathValidationResult::class, $result);
        return $result;
    }

    /**
     * @depends validateDefault
     *
     * @test
     */
    public function result(PathValidationResult $result)
    {
        $expected_cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        static::assertEquals($expected_cert, $result->certificate());
    }

    /**
     * @test
     */
    public function validateExpired()
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(new DateTimeImmutable('2026-01-03'));
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    /**
     * @test
     */
    public function validateNotBeforeFail()
    {
        $config = PathValidationConfig::defaultConfig()->withDateTime(new DateTimeImmutable('2015-12-31'));
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    /**
     * @test
     */
    public function validatePathLengthFail()
    {
        $config = PathValidationConfig::defaultConfig()->withMaxLength(0);
        $this->expectException(PathValidationException::class);
        self::$_path->validate($config);
    }

    /**
     * @test
     */
    public function noCertsFail()
    {
        $this->expectException(LogicException::class);
        new PathValidator(Crypto::getDefault(), PathValidationConfig::defaultConfig());
    }

    /**
     * @test
     */
    public function explicitTrustAnchor()
    {
        $config = PathValidationConfig::defaultConfig()->withTrustAnchor(self::$_path->certificates()[0]);
        $validator = new PathValidator(Crypto::getDefault(), $config, ...self::$_path->certificates());
        static::assertInstanceOf(PathValidationResult::class, $validator->validate());
    }
}
