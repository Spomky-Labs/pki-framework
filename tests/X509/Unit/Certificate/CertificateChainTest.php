<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateChain;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use function sprintf;

/**
 * @internal
 */
final class CertificateChainTest extends TestCase
{
    /**
     * @var PEM[]|null
     */
    private static ?array $_pems = null;

    /**
     * @var Certificate[]|null
     */
    private static ?array $_certs = null;

    public static function setUpBeforeClass(): void
    {
        self::$_pems = [
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'),
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem'),
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'), ];
        self::$_certs = array_map(Certificate::fromPEM(...), self::$_pems);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pems = null;
        self::$_certs = null;
    }

    #[Test]
    public function createChain(): CertificateChain
    {
        $chain = CertificateChain::create(...self::$_certs);
        static::assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    #[Test]
    #[Depends('createChain')]
    public function certificates(CertificateChain $chain)
    {
        $chain->certificates();
        static::assertContainsOnlyInstancesOf(Certificate::class, $chain);
    }

    #[Test]
    #[Depends('createChain')]
    public function endEntityCert(CertificateChain $chain)
    {
        static::assertEquals(self::$_certs[0], $chain->endEntityCertificate());
    }

    #[Test]
    public function endEntityCertFail()
    {
        $chain = CertificateChain::create();
        $this->expectException(LogicException::class);
        $chain->endEntityCertificate();
    }

    #[Test]
    #[Depends('createChain')]
    public function trustAnchorCert(CertificateChain $chain)
    {
        static::assertEquals(self::$_certs[2], $chain->trustAnchorCertificate());
    }

    #[Test]
    public function trustAnchorCertFail()
    {
        $chain = CertificateChain::create();
        $this->expectException(LogicException::class);
        $chain->trustAnchorCertificate();
    }

    #[Test]
    #[Depends('createChain')]
    public function countMethod(CertificateChain $chain)
    {
        static::assertCount(3, $chain);
    }

    #[Test]
    #[Depends('createChain')]
    public function iterator(CertificateChain $chain)
    {
        $certs = [];
        foreach ($chain as $cert) {
            $certs[] = $cert;
        }
        static::assertContainsOnlyInstancesOf(Certificate::class, $certs);
    }

    #[Test]
    public function fromPEMs()
    {
        $chain = CertificateChain::fromPEMs(...self::$_pems);
        static::assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    #[Test]
    #[Depends('createChain')]
    #[Depends('fromPEMs')]
    public function fromPEMEquals(CertificateChain $ref, CertificateChain $chain)
    {
        static::assertEquals($ref, $chain);
    }

    #[Test]
    #[Depends('createChain')]
    public function toPEMString(CertificateChain $chain)
    {
        $expected = sprintf("%s\n%s\n%s", self::$_pems[0], self::$_pems[1], self::$_pems[2]);
        $str = $chain->toPEMString();
        static::assertSame($expected, $str);
        return $str;
    }

    /**
     * @param string $str
     */
    #[Test]
    #[Depends('toPEMString')]
    public function fromPEMString($str)
    {
        $chain = CertificateChain::fromPEMString($str);
        static::assertInstanceOf(CertificateChain::class, $chain);
        return $chain;
    }

    #[Test]
    #[Depends('createChain')]
    #[Depends('fromPEMString')]
    public function fromPEMStringEquals(CertificateChain $ref, CertificateChain $chain)
    {
        static::assertEquals($ref, $chain);
    }

    #[Test]
    #[Depends('createChain')]
    public function certificationPath(CertificateChain $chain)
    {
        $path = $chain->certificationPath();
        static::assertInstanceOf(CertificationPath::class, $path);
    }
}
