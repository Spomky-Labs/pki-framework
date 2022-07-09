<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateBundle;
use Sop\X509\Certificate\CertificateChain;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\PathValidation\PathValidationConfig;
use Sop\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * @internal
 */
final class CertificationPathTest extends TestCase
{
    private static $_certs;

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
        $path = new CertificationPath(...self::$_certs);
        $this->assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(CertificationPath $path)
    {
        $this->assertCount(3, $path);
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
        $this->assertCount(3, $values);
        $this->assertContainsOnlyInstancesOf(Certificate::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function validate(CertificationPath $path)
    {
        $result = $path->validate(PathValidationConfig::defaultConfig());
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }

    /**
     * @test
     */
    public function fromTrustAnchorToTarget()
    {
        $path = CertificationPath::fromTrustAnchorToTarget(
            self::$_certs[0],
            self::$_certs[2],
            new CertificateBundle(...self::$_certs)
        );
        $this->assertInstanceOf(CertificationPath::class, $path);
    }

    /**
     * @test
     */
    public function fromCertificateChain()
    {
        $chain = new CertificateChain(...array_reverse(self::$_certs, false));
        $path = CertificationPath::fromCertificateChain($chain);
        $this->assertInstanceOf(CertificationPath::class, $path);
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
        $this->assertEquals($ref, $path);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function trustAnchor(CertificationPath $path)
    {
        $cert = $path->trustAnchorCertificate();
        $this->assertEquals(self::$_certs[0], $cert);
    }

    /**
     * @test
     */
    public function trustAnchorFail()
    {
        $path = new CertificationPath();
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
        $this->assertEquals(self::$_certs[2], $cert);
    }

    /**
     * @test
     */
    public function endEntityFail()
    {
        $path = new CertificationPath();
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
        $this->assertInstanceOf(CertificateChain::class, $chain);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithSingle(CertificationPath $path)
    {
        $this->assertTrue($path->startsWith(self::$_certs[0]));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithMulti(CertificationPath $path)
    {
        $this->assertTrue($path->startsWith(...array_slice(self::$_certs, 0, 2, false)));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithAll(CertificationPath $path)
    {
        $this->assertTrue($path->startsWith(...self::$_certs));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithTooManyFail(CertificationPath $path)
    {
        $this->assertFalse($path->startsWith(...array_merge(self::$_certs, [self::$_certs[0]])));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function startWithFail(CertificationPath $path)
    {
        $this->assertFalse($path->startsWith(self::$_certs[1]));
    }
}
