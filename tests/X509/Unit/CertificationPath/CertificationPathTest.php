<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\CertificateChain;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use function array_slice;

/**
 * @internal
 */
final class CertificationPathTest extends TestCase
{
    /**
     * @var Certificate[]|null
     */
    private static ?array $_certs = null;

    public static function setUpBeforeClass(): void
    {
        self::$_certs = [
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem')),
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem')),
            Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem')), ];
    }

    public static function tearDownAfterClass(): void
    {
        self::$_certs = null;
    }

    #[Test]
    public function create(): CertificationPath
    {
        $path = CertificationPath::create(...self::$_certs);
        static::assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    #[Test]
    #[Depends('create')]
    public function countMethod(CertificationPath $path)
    {
        static::assertCount(3, $path);
    }

    #[Test]
    #[Depends('create')]
    public function iterator(CertificationPath $path)
    {
        $values = [];
        foreach ($path as $cert) {
            $values[] = $cert;
        }
        static::assertCount(3, $values);
        static::assertContainsOnlyInstancesOf(Certificate::class, $values);
    }

    #[Test]
    #[Depends('create')]
    public function validate(CertificationPath $path)
    {
        $result = $path->validate(PathValidationConfig::defaultConfig());
        static::assertInstanceOf(PathValidationResult::class, $result);
    }

    #[Test]
    public function fromTrustAnchorToTarget()
    {
        $path = CertificationPath::fromTrustAnchorToTarget(
            self::$_certs[0],
            self::$_certs[2],
            CertificateBundle::create(...self::$_certs)
        );
        static::assertInstanceOf(CertificationPath::class, $path);
    }

    #[Test]
    public function fromCertificateChain()
    {
        $chain = CertificateChain::create(...array_reverse(self::$_certs, false));
        $path = CertificationPath::fromCertificateChain($chain);
        static::assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('fromCertificateChain')]
    public function fromChainEquals(CertificationPath $ref, CertificationPath $path)
    {
        static::assertEquals($ref, $path);
    }

    #[Test]
    #[Depends('create')]
    public function trustAnchor(CertificationPath $path)
    {
        $cert = $path->trustAnchorCertificate();
        static::assertEquals(self::$_certs[0], $cert);
    }

    #[Test]
    public function trustAnchorFail()
    {
        $path = CertificationPath::create();
        $this->expectException(LogicException::class);
        $path->trustAnchorCertificate();
    }

    #[Test]
    #[Depends('create')]
    public function endEntity(CertificationPath $path)
    {
        $cert = $path->endEntityCertificate();
        static::assertEquals(self::$_certs[2], $cert);
    }

    #[Test]
    public function endEntityFail()
    {
        $path = CertificationPath::create();
        $this->expectException(LogicException::class);
        $path->endEntityCertificate();
    }

    #[Test]
    #[Depends('create')]
    public function certificateChain(CertificationPath $path)
    {
        $chain = $path->certificateChain();
        static::assertInstanceOf(CertificateChain::class, $chain);
    }

    #[Test]
    #[Depends('create')]
    public function startWithSingle(CertificationPath $path)
    {
        static::assertTrue($path->startsWith(self::$_certs[0]));
    }

    #[Test]
    #[Depends('create')]
    public function startWithMulti(CertificationPath $path)
    {
        static::assertTrue($path->startsWith(...array_slice(self::$_certs, 0, 2, false)));
    }

    #[Test]
    #[Depends('create')]
    public function startWithAll(CertificationPath $path)
    {
        static::assertTrue($path->startsWith(...self::$_certs));
    }

    #[Test]
    #[Depends('create')]
    public function startWithTooManyFail(CertificationPath $path)
    {
        static::assertFalse($path->startsWith(...array_merge(self::$_certs, [self::$_certs[0]])));
    }

    #[Test]
    #[Depends('create')]
    public function startWithFail(CertificationPath $path)
    {
        static::assertFalse($path->startsWith(self::$_certs[1]));
    }
}
