<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\CertificationPath;

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateBundle;
use Sop\X509\CertificationPath\CertificationPath;
use Sop\X509\CertificationPath\Exception\PathBuildingException;
use Sop\X509\CertificationPath\PathBuilding\CertificationPathBuilder;

/**
 * @internal
 */
final class CertificationPathBuildingTest extends TestCase
{
    private static $_ca;

    private static $_interm;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_ca = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        self::$_interm = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem'));
        self::$_cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_ca = null;
        self::$_interm = null;
        self::$_cert = null;
    }

    /**
     * @test
     */
    public function buildPath()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_cert, new CertificateBundle(self::$_interm));
        $this->assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathLength(CertificationPath $path)
    {
        $this->assertCount(3, $path);
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathAnchor(CertificationPath $path)
    {
        $this->assertEquals(self::$_ca, $path->certificates()[0]);
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathIntermediate(CertificationPath $path)
    {
        $this->assertEquals(self::$_interm, $path->certificates()[1]);
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathTarget(CertificationPath $path)
    {
        $this->assertEquals(self::$_cert, $path->certificates()[2]);
    }

    /**
     * @test
     */
    public function buildPathFail()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca));
        $this->expectException(PathBuildingException::class);
        $builder->shortestPathToTarget(self::$_cert, new CertificateBundle());
    }

    /**
     * @test
     */
    public function buildSelfSigned()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_ca);
        $this->assertCount(1, $path);
    }

    /**
     * @test
     */
    public function buildLength2()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_interm);
        $this->assertCount(2, $path);
    }

    /**
     * @test
     */
    public function buildWithCAInIntermediate()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_cert, new CertificateBundle(self::$_ca, self::$_interm));
        $this->assertCount(3, $path);
    }

    /**
     * @test
     */
    public function buildMultipleChoices()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca, self::$_interm));
        $paths = $builder->allPathsToTarget(self::$_cert, new CertificateBundle(self::$_interm));
        $this->assertCount(2, $paths);
        $this->assertContainsOnlyInstancesOf(CertificationPath::class, $paths);
    }

    /**
     * @test
     */
    public function buildShortest()
    {
        $builder = new CertificationPathBuilder(new CertificateBundle(self::$_ca, self::$_interm));
        $path = $builder->shortestPathToTarget(self::$_cert, new CertificateBundle(self::$_interm));
        $this->assertCount(2, $path);
    }
}
