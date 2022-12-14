<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath;

use function array_slice;
use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\CertificateChain;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

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

    /**
     * @test
     */
    public function create()
    {
        $path = CertificationPath::create(...self::$_certs);
        static::assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(CertificationPath $path)
    {
        static::assertCount(3, $path);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(CertificationPath $path)
    {
        $values = [];
        foreach ($path as $cert) {
            $values[] = $cert;
        }
        static::assertCount(3, $values);
        static::assertContainsOnlyInstancesOf(Certificate::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function validate(CertificationPath $path)
    {
        $result = $path->validate(PathValidationConfig::defaultConfig());
        static::assertInstanceOf(PathValidationResult::class, $result);
    }

    /**
     * @test
     */
    public function fromTrustAnchorToTarget()
    {
        $path = CertificationPath::fromTrustAnchorToTarget(
            self::$_certs[0],
            self::$_certs[2],
            CertificateBundle::create(...self::$_certs)
        );
        static::assertInstanceOf(CertificationPath::class, $path);
    }

    /**
     * @test
     */
    public function fromCertificateChain()
    {
        $chain = CertificateChain::create(...array_reverse(self::$_certs, false));
        $path = CertificationPath::fromCertificateChain($chain);
        static::assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends create
     * @depends fromCertificateChain
     *
     * @test
     */
    public function fromChainEquals(CertificationPath $ref, CertificationPath $path)
    {
        static::assertEquals($ref, $path);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function trustAnchor(CertificationPath $path)
    {
        $cert = $path->trustAnchorCertificate();
        static::assertEquals(self::$_certs[0], $cert);
    }

    /**
     * @test
     */
    public function trustAnchorFail()
    {
        $path = CertificationPath::create();
        $this->expectException(LogicException::class);
        $path->trustAnchorCertificate();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function endEntity(CertificationPath $path)
    {
        $cert = $path->endEntityCertificate();
        static::assertEquals(self::$_certs[2], $cert);
    }

    /**
     * @test
     */
    public function endEntityFail()
    {
        $path = CertificationPath::create();
        $this->expectException(LogicException::class);
        $path->endEntityCertificate();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function certificateChain(CertificationPath $path)
    {
        $chain = $path->certificateChain();
        static::assertInstanceOf(CertificateChain::class, $chain);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithSingle(CertificationPath $path)
    {
        static::assertTrue($path->startsWith(self::$_certs[0]));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithMulti(CertificationPath $path)
    {
        static::assertTrue($path->startsWith(...array_slice(self::$_certs, 0, 2, false)));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithAll(CertificationPath $path)
    {
        static::assertTrue($path->startsWith(...self::$_certs));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithTooManyFail(CertificationPath $path)
    {
        static::assertFalse($path->startsWith(...array_merge(self::$_certs, [self::$_certs[0]])));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithFail(CertificationPath $path)
    {
        static::assertFalse($path->startsWith(self::$_certs[1]));
    }
}
