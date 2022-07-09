<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath\Validation;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;

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
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function maxLength(PathValidationConfig $config)
    {
        $this->assertEquals(3, $config->maxLength());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function dateTime(PathValidationConfig $config)
    {
        $this->assertInstanceOf(DateTimeImmutable::class, $config->dateTime());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function policySet(PathValidationConfig $config)
    {
        $this->assertContainsOnly('string', $config->policySet());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withMaxLength(PathValidationConfig $config)
    {
        $config = $config->withMaxLength(5);
        $this->assertInstanceOf(PathValidationConfig::class, $config);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withDateTime(PathValidationConfig $config)
    {
        $config = $config->withDateTime(new DateTimeImmutable());
        $this->assertInstanceOf(PathValidationConfig::class, $config);
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
        $this->assertInstanceOf(PathValidationConfig::class, $config);
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
        $this->assertInstanceOf(PathValidationConfig::class, $config);
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
        $this->assertInstanceOf(PathValidationConfig::class, $config);
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
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends withTrustAnchor
     *
     * @test
     */
    public function trustAnchor(PathValidationConfig $config)
    {
        $this->assertInstanceOf(Certificate::class, $config->trustAnchor());
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
        $this->assertIsBool($config->policyMappingInhibit());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function explicitPolicy(PathValidationConfig $config)
    {
        $this->assertIsBool($config->explicitPolicy());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function anyPolicyInhibit(PathValidationConfig $config)
    {
        $this->assertIsBool($config->anyPolicyInhibit());
    }
}
