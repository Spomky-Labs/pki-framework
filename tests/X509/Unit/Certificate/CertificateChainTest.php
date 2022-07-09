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

    public function testCreateChain()
    {
        $chain = new CertificateChain(...self::$_certs);
        $this->assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    /**
     * @depends testCreateChain
     */
    public function testCertificates(CertificateChain $chain)
    {
        $chain->certificates();
        $this->assertContainsOnlyInstancesOf(Certificate::class, $chain);
    }

    /**
     * @depends testCreateChain
     */
    public function testEndEntityCert(CertificateChain $chain)
    {
        $this->assertEquals(self::$_certs[0], $chain->endEntityCertificate());
    }

    public function testEndEntityCertFail()
    {
        $chain = new CertificateChain();
        $this->expectException(LogicException::class);
        $chain->endEntityCertificate();
    }

    /**
     * @depends testCreateChain
     */
    public function testTrustAnchorCert(CertificateChain $chain)
    {
        $this->assertEquals(self::$_certs[2], $chain->trustAnchorCertificate());
    }

    public function testTrustAnchorCertFail()
    {
        $chain = new CertificateChain();
        $this->expectException(LogicException::class);
        $chain->trustAnchorCertificate();
    }

    /**
     * @depends testCreateChain
     */
    public function testCount(CertificateChain $chain)
    {
        $this->assertCount(3, $chain);
    }

    /**
     * @depends testCreateChain
     */
    public function testIterator(CertificateChain $chain)
    {
        $certs = [];
        foreach ($chain as $cert) {
            $certs[] = $cert;
        }
        $this->assertContainsOnlyInstancesOf(Certificate::class, $certs);
    }

    public function testFromPEMs()
    {
        $chain = CertificateChain::fromPEMs(...self::$_pems);
        $this->assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    /**
     * @depends testCreateChain
     * @depends testFromPEMs
     */
    public function testFromPEMEquals(CertificateChain $ref, CertificateChain $chain)
    {
        $this->assertEquals($ref, $chain);
    }

    /**
     * @depends testCreateChain
     */
    public function testToPEMString(CertificateChain $chain)
    {
        $expected = sprintf("%s\n%s\n%s", self::$_pems[0], self::$_pems[1], self::$_pems[2]);
        $str = $chain->toPEMString();
        $this->assertEquals($expected, $str);
        return $str;
    }

    /**
     * @depends testToPEMString
     *
     * @param string $str
     */
    public function testFromPEMString($str)
    {
        $chain = CertificateChain::fromPEMString($str);
        $this->assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    /**
     * @depends testCreateChain
     * @depends testFromPEMString
     */
    public function testFromPEMStringEquals(CertificateChain $ref, CertificateChain $chain)
    {
        $this->assertEquals($ref, $chain);
    }

    /**
     * @depends testCreateChain
     */
    public function testCertificationPath(CertificateChain $chain)
    {
        $path = $chain->certificationPath();
        $this->assertInstanceOf(CertificationPath::class, $path);
    }
}
