<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath\Validation;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * @group certification-path
 *
 * @internal
 */
class PathValidationConfigTest extends TestCase
{
    public function testCreate()
    {
        $config = PathValidationConfig::defaultConfig();
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testMaxLength(PathValidationConfig $config)
    {
        $this->assertEquals(3, $config->maxLength());
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testDateTime(PathValidationConfig $config)
    {
        $this->assertInstanceOf(\DateTimeImmutable::class, $config->dateTime());
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testPolicySet(PathValidationConfig $config)
    {
        $this->assertContainsOnly('string', $config->policySet());
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testWithMaxLength(PathValidationConfig $config)
    {
        $config = $config->withMaxLength(5);
        $this->assertInstanceOf(PathValidationConfig::class, $config);
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testWithDateTime(PathValidationConfig $config)
    {
        $config = $config->withDateTime(new \DateTimeImmutable());
        $this->assertInstanceOf(PathValidationConfig::class, $config);
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testWithTrustAnchor(PathValidationConfig $config)
    {
        $config = $config->withTrustAnchor(
            Certificate::fromPEM(
                PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem')));
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testWithPolicyMappingInhibit(PathValidationConfig $config)
    {
        $config = $config->withPolicyMappingInhibit(true);
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testWithExplicitPolicy(PathValidationConfig $config)
    {
        $config = $config->withExplicitPolicy(true);
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testWithAnyPolicyInhibit(PathValidationConfig $config)
    {
        $config = $config->withAnyPolicyInhibit(true);
        $this->assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    /**
     * @depends testWithTrustAnchor
     *
     * @param PathValidationConfig $config
     */
    public function testTrustAnchor(PathValidationConfig $config)
    {
        $this->assertInstanceOf(Certificate::class, $config->trustAnchor());
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testTrustAnchorFail(PathValidationConfig $config)
    {
        $this->expectException(\LogicException::class);
        $config->trustAnchor();
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testPolicyMappingInhibit(PathValidationConfig $config)
    {
        $this->assertIsBool($config->policyMappingInhibit());
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testExplicitPolicy(PathValidationConfig $config)
    {
        $this->assertIsBool($config->explicitPolicy());
    }

    /**
     * @depends testCreate
     *
     * @param PathValidationConfig $config
     */
    public function testAnyPolicyInhibit(PathValidationConfig $config)
    {
        $this->assertIsBool($config->anyPolicyInhibit());
    }
}
