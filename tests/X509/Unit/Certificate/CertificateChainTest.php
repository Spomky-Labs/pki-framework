<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Certificate;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\CertificateChain;
use Sop\X509\CertificationPath\CertificationPath;

/**
 * @internal
 */
final class CertificateChainTest extends TestCase
{
    private static $_pems;

    private static $_certs;

    public static function setUpBeforeClass(): void
    {
        self::$_pems = [
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'),
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem'),
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'), ];
        self::$_certs = array_map(fn (PEM $pem) => Certificate::fromPEM($pem), self::$_pems);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pems = null;
        self::$_certs = null;
    }

    /**
     * @test
     */
    public function createChain()
    {
        $chain = new CertificateChain(...self::$_certs);
        static::assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function certificates(CertificateChain $chain)
    {
        $chain->certificates();
        static::assertContainsOnlyInstancesOf(Certificate::class, $chain);
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function endEntityCert(CertificateChain $chain)
    {
        static::assertEquals(self::$_certs[0], $chain->endEntityCertificate());
    }

    /**
     * @test
     */
    public function endEntityCertFail()
    {
        $chain = new CertificateChain();
        $this->expectException(LogicException::class);
        $chain->endEntityCertificate();
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function trustAnchorCert(CertificateChain $chain)
    {
        static::assertEquals(self::$_certs[2], $chain->trustAnchorCertificate());
    }

    /**
     * @test
     */
    public function trustAnchorCertFail()
    {
        $chain = new CertificateChain();
        $this->expectException(LogicException::class);
        $chain->trustAnchorCertificate();
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function countMethod(CertificateChain $chain)
    {
        static::assertCount(3, $chain);
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function iterator(CertificateChain $chain)
    {
        $certs = [];
        foreach ($chain as $cert) {
            $certs[] = $cert;
        }
        static::assertContainsOnlyInstancesOf(Certificate::class, $certs);
    }

    /**
     * @test
     */
    public function fromPEMs()
    {
        $chain = CertificateChain::fromPEMs(...self::$_pems);
        static::assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    /**
     * @depends createChain
     * @depends fromPEMs
     *
     * @test
     */
    public function fromPEMEquals(CertificateChain $ref, CertificateChain $chain)
    {
        static::assertEquals($ref, $chain);
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function toPEMString(CertificateChain $chain)
    {
        $expected = sprintf("%s\n%s\n%s", self::$_pems[0], self::$_pems[1], self::$_pems[2]);
        $str = $chain->toPEMString();
        static::assertEquals($expected, $str);
        return $str;
    }

    /**
     * @depends toPEMString
     *
     * @param string $str
     *
     * @test
     */
    public function fromPEMString($str)
    {
        $chain = CertificateChain::fromPEMString($str);
        static::assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    /**
     * @depends createChain
     * @depends fromPEMString
     *
     * @test
     */
    public function fromPEMStringEquals(CertificateChain $ref, CertificateChain $chain)
    {
        static::assertEquals($ref, $chain);
    }

    /**
     * @depends createChain
     *
     * @test
     */
    public function certificationPath(CertificateChain $chain)
    {
        $path = $chain->certificationPath();
        static::assertInstanceOf(CertificationPath::class, $path);
    }
}
