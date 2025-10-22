<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath\Validation;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * @internal
 */
final class PathValidationConfigTest extends TestCase
{
    #[Test]
    public function create(): PathValidationConfig
    {
        $config = PathValidationConfig::defaultConfig();
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    #[Test]
    #[Depends('create')]
    public function maxLength(PathValidationConfig $config)
    {
        static::assertSame(3, $config->maxLength());
    }

    #[Test]
    #[Depends('create')]
    public function dateTime(PathValidationConfig $config)
    {
        static::assertInstanceOf(DateTimeImmutable::class, $config->dateTime());
    }

    #[Test]
    #[Depends('create')]
    public function policySet(PathValidationConfig $config)
    {
        static::assertContainsOnly('string', $config->policySet());
    }

    #[Test]
    #[Depends('create')]
    public function withMaxLength(PathValidationConfig $config)
    {
        $config = $config->withMaxLength(5);
        static::assertInstanceOf(PathValidationConfig::class, $config);
    }

    #[Test]
    #[Depends('create')]
    public function withDateTime(PathValidationConfig $config)
    {
        $config = $config->withDateTime(new DateTimeImmutable());
        static::assertInstanceOf(PathValidationConfig::class, $config);
    }

    #[Test]
    #[Depends('create')]
    public function withTrustAnchor(PathValidationConfig $config)
    {
        $config = $config->withTrustAnchor(
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'))
        );
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    #[Test]
    #[Depends('create')]
    public function withPolicyMappingInhibit(PathValidationConfig $config)
    {
        $config = $config->withPolicyMappingInhibit(true);
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    #[Test]
    #[Depends('create')]
    public function withExplicitPolicy(PathValidationConfig $config)
    {
        $config = $config->withExplicitPolicy(true);
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    #[Test]
    #[Depends('create')]
    public function withAnyPolicyInhibit(PathValidationConfig $config)
    {
        $config = $config->withAnyPolicyInhibit(true);
        static::assertInstanceOf(PathValidationConfig::class, $config);
        return $config;
    }

    #[Test]
    #[Depends('withTrustAnchor')]
    public function trustAnchor(PathValidationConfig $config)
    {
        static::assertInstanceOf(Certificate::class, $config->trustAnchor());
    }

    #[Test]
    #[Depends('create')]
    public function trustAnchorFail(PathValidationConfig $config)
    {
        $this->expectException(LogicException::class);
        $config->trustAnchor();
    }

    #[Test]
    #[Depends('create')]
    public function policyMappingInhibit(PathValidationConfig $config)
    {
        static::assertIsBool($config->policyMappingInhibit());
    }

    #[Test]
    #[Depends('create')]
    public function explicitPolicy(PathValidationConfig $config)
    {
        static::assertIsBool($config->explicitPolicy());
    }

    #[Test]
    #[Depends('create')]
    public function anyPolicyInhibit(PathValidationConfig $config)
    {
        static::assertIsBool($config->anyPolicyInhibit());
    }
}
