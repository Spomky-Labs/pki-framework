<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath\Validation;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * @internal
 */
final class PathValidationConfigTest extends TestCase
{
    /**
     * @test
     */
    public function create()
    {
        $config = PathValidationConfig::defaultConfig();
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function maxLength(PathValidationConfig $config)
    {
        static::assertEquals(3, $config->maxLength());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function dateTime(PathValidationConfig $config)
    {
        static::assertInstanceOf(DateTimeImmutable::class, $config->dateTime());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function policySet(PathValidationConfig $config)
    {
        static::assertContainsOnly('string', $config->policySet());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withMaxLength(PathValidationConfig $config)
    {
        $config = $config->withMaxLength(5);
        static::assertInstanceOf(PathValidationConfig::class, $config);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withDateTime(PathValidationConfig $config)
    {
        $config = $config->withDateTime(new DateTimeImmutable());
        static::assertInstanceOf(PathValidationConfig::class, $config);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withTrustAnchor(PathValidationConfig $config)
    {
        $config = $config->withTrustAnchor(
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'))
        );
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withPolicyMappingInhibit(PathValidationConfig $config)
    {
        $config = $config->withPolicyMappingInhibit(true);
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withExplicitPolicy(PathValidationConfig $config)
    {
        $config = $config->withExplicitPolicy(true);
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAnyPolicyInhibit(PathValidationConfig $config)
    {
        $config = $config->withAnyPolicyInhibit(true);
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends withTrustAnchor
     *
     * @test
     */
    public function trustAnchor(PathValidationConfig $config)
    {
        static::assertInstanceOf(Certificate::class, $config->trustAnchor());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function trustAnchorFail(PathValidationConfig $config)
    {
        $this->expectException(LogicException::class);
        $config->trustAnchor();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function policyMappingInhibit(PathValidationConfig $config)
    {
        static::assertIsBool($config->policyMappingInhibit());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function explicitPolicy(PathValidationConfig $config)
    {
        static::assertIsBool($config->explicitPolicy());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function anyPolicyInhibit(PathValidationConfig $config)
    {
        static::assertIsBool($config->anyPolicyInhibit());
    }
}
