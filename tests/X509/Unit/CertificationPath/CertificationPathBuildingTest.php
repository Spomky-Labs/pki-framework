<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathBuildingException;
use SpomkyLabs\Pki\X509\CertificationPath\PathBuilding\CertificationPathBuilder;

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
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_cert, CertificateBundle::create(self::$_interm));
        static::assertInstanceOf(CertificationPath::class, $path);
        return $path;
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathLength(CertificationPath $path)
    {
        static::assertCount(3, $path);
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathAnchor(CertificationPath $path)
    {
        static::assertEquals(self::$_ca, $path->certificates()[0]);
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathIntermediate(CertificationPath $path)
    {
        static::assertEquals(self::$_interm, $path->certificates()[1]);
    }

    /**
     * @depends buildPath
     *
     * @test
     */
    public function pathTarget(CertificationPath $path)
    {
        static::assertEquals(self::$_cert, $path->certificates()[2]);
    }

    /**
     * @test
     */
    public function buildPathFail()
    {
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca));
        $this->expectException(PathBuildingException::class);
        $builder->shortestPathToTarget(self::$_cert, CertificateBundle::create());
    }

    /**
     * @test
     */
    public function buildSelfSigned()
    {
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_ca);
        static::assertCount(1, $path);
    }

    /**
     * @test
     */
    public function buildLength2()
    {
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_interm);
        static::assertCount(2, $path);
    }

    /**
     * @test
     */
    public function buildWithCAInIntermediate()
    {
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca));
        $path = $builder->shortestPathToTarget(self::$_cert, CertificateBundle::create(self::$_ca, self::$_interm));
        static::assertCount(3, $path);
    }

    /**
     * @test
     */
    public function buildMultipleChoices()
    {
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca, self::$_interm));
        $paths = $builder->allPathsToTarget(self::$_cert, CertificateBundle::create(self::$_interm));
        static::assertCount(2, $paths);
        static::assertContainsOnlyInstancesOf(CertificationPath::class, $paths);
    }

    /**
     * @test
     */
    public function buildShortest()
    {
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_ca, self::$_interm));
        $path = $builder->shortestPathToTarget(self::$_cert, CertificateBundle::create(self::$_interm));
        static::assertCount(2, $path);
    }
}
