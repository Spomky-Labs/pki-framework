<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * @internal
 */
final class CertificateBundleTest extends TestCase
{
    private static $_pem1;

    private static $_cert1;

    private static $_pem2;

    private static $_cert2;

    private static $_pem3;

    private static $_cert3;

    public static function setUpBeforeClass(): void
    {
        self::$_pem1 = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem');
        self::$_cert1 = Certificate::fromPEM(self::$_pem1);
        self::$_pem2 = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-rsa.pem');
        self::$_cert2 = Certificate::fromPEM(self::$_pem2);
        self::$_pem3 = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem');
        self::$_cert3 = Certificate::fromPEM(self::$_pem3);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pem1 = null;
        self::$_cert1 = null;
        self::$_pem2 = null;
        self::$_cert2 = null;
        self::$_pem3 = null;
        self::$_cert3 = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $bundle = new CertificateBundle(self::$_cert1, self::$_cert2);
        static::assertInstanceOf(CertificateBundle::class, $bundle);
        return $bundle;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function countMethod(CertificateBundle $bundle)
    {
        static::assertCount(2, $bundle);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function all(CertificateBundle $bundle)
    {
        static::assertCount(2, $bundle->all());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function iterator(CertificateBundle $bundle)
    {
        $values = [];
        foreach ($bundle as $cert) {
            $values[] = $cert;
        }
        static::assertCount(2, $values);
        static::assertContainsOnlyInstancesOf(Certificate::class, $values);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function contains(CertificateBundle $bundle)
    {
        static::assertTrue($bundle->contains(self::$_cert1));
    }

    /**
     * @test
     */
    public function doesNotContain()
    {
        $bundle = new CertificateBundle(self::$_cert1, self::$_cert2);
        static::assertFalse($bundle->contains(self::$_cert3));
    }

    /**
     * @test
     */
    public function containsSubjectMismatch()
    {
        $priv_key_info = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $tc = new TBSCertificate(
            Name::fromString('cn=Subject'),
            $priv_key_info->publicKeyInfo(),
            Name::fromString('cn=Issuer 1'),
            Validity::fromStrings(null, null)
        );
        $cert1 = $tc->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), $priv_key_info);
        $tc = $tc->withSubject(Name::fromString('cn=Issuer 2'));
        $cert2 = $tc->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), $priv_key_info);
        $bundle = new CertificateBundle($cert1);
        static::assertFalse($bundle->contains($cert2));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function allBySubjectKeyID(CertificateBundle $bundle)
    {
        $id = self::$_cert2->tbsCertificate()
            ->extensions()
            ->subjectKeyIdentifier()
            ->keyIdentifier();
        $certs = $bundle->allBySubjectKeyIdentifier($id);
        static::assertCount(1, $certs);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withPEM(CertificateBundle $bundle)
    {
        $bundle = $bundle->withPEM(self::$_pem3);
        static::assertCount(3, $bundle);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withPEMBundle(CertificateBundle $bundle)
    {
        $bundle = $bundle->withPEMBundle(new PEMBundle(self::$_pem3));
        static::assertCount(3, $bundle);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withCertificates(CertificateBundle $bundle)
    {
        $bundle = $bundle->withCertificates(Certificate::fromPEM(self::$_pem3));
        static::assertCount(3, $bundle);
    }

    /**
     * @test
     */
    public function fromPEMBundle()
    {
        $bundle = CertificateBundle::fromPEMBundle(new PEMBundle(self::$_pem1, self::$_pem2));
        static::assertInstanceOf(CertificateBundle::class, $bundle);
    }

    /**
     * @test
     */
    public function fromPEMs()
    {
        $bundle = CertificateBundle::fromPEMs(self::$_pem1, self::$_pem2);
        static::assertInstanceOf(CertificateBundle::class, $bundle);
    }

    /**
     * @test
     */
    public function searchBySubjectKeyHavingNoID()
    {
        $priv_key_info = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $tc = new TBSCertificate(
            Name::fromString('cn=Subject'),
            $priv_key_info->publicKeyInfo(),
            Name::fromString('cn=Issuer'),
            Validity::fromStrings(null, null)
        );
        $cert = $tc->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), $priv_key_info);
        $bundle = new CertificateBundle($cert);
        static::assertEmpty($bundle->allBySubjectKeyIdentifier('nope'));
    }
}
