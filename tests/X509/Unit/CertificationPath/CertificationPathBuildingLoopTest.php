<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\CertificationPath;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathBuildingException;
use SpomkyLabs\Pki\X509\CertificationPath\PathBuilding\CertificationPathBuilder;

/**
 * Covers the termination of the certification path resolution.
 *
 * The intermediate bundle comes from the peer in every common scenario, so it must not be able to drive the builder
 * into an endless recursion nor into a combinatorial explosion.
 *
 * @see https://tools.ietf.org/html/rfc4158#section-2.4.2
 *
 * @internal
 */
final class CertificationPathBuildingLoopTest extends TestCase
{
    private static ?PrivateKeyInfo $_key = null;

    private static ?Certificate $_root = null;

    public static function setUpBeforeClass(): void
    {
        self::$_key = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        self::$_root = self::createCertificate('cn=Root', 'cn=Root', 'root-key-id', 'root-key-id', 1);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_key = null;
        self::$_root = null;
    }

    #[Test]
    public function mutuallyIssuingCertificatesDoNotLoop()
    {
        // A is issued by B and B is issued by A, neither is self-issued
        $a = self::createCertificate('cn=A', 'cn=B', 'a-key-id', 'b-key-id', 10);
        $b = self::createCertificate('cn=B', 'cn=A', 'b-key-id', 'a-key-id', 11);
        $target = self::createCertificate('cn=EE', 'cn=A', 'ee-key-id', 'a-key-id', 12);
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_root));
        $paths = $builder->allPathsToTarget($target, CertificateBundle::create($a, $b));
        static::assertSame([], $paths);
    }

    #[Test]
    public function pathIsBuiltThroughABundleHoldingALoop()
    {
        // the same loop, but this time A is issued by the trust anchor as well
        $a = self::createCertificate('cn=A', 'cn=B', 'a-key-id', 'b-key-id', 10);
        $b = self::createCertificate('cn=B', 'cn=A', 'b-key-id', 'a-key-id', 11);
        $interm = self::createCertificate('cn=Interm', 'cn=Root', 'interm-key-id', 'root-key-id', 13);
        $target = self::createCertificate('cn=EE', 'cn=Interm', 'ee-key-id', 'interm-key-id', 14);
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_root));
        $paths = $builder->allPathsToTarget($target, CertificateBundle::create($a, $b, $interm));
        static::assertCount(1, $paths);
        static::assertCount(3, $paths[0]);
    }

    #[Test]
    public function chainLongerThanTheMaximumLengthIsAbandoned()
    {
        // a chain of 12 intermediate certificates leading to the trust anchor
        $intermediates = [];
        $issuerKeyId = 'root-key-id';
        $issuerName = 'cn=Root';
        for ($i = 12; $i > 0; --$i) {
            $intermediates[] = self::createCertificate(
                "cn=I{$i}",
                $issuerName,
                "i{$i}-key-id",
                $issuerKeyId,
                100 + $i
            );
            $issuerName = "cn=I{$i}";
            $issuerKeyId = "i{$i}-key-id";
        }
        $target = self::createCertificate('cn=EE', $issuerName, 'ee-key-id', $issuerKeyId, 200);
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_root));
        $paths = $builder->allPathsToTarget($target, CertificateBundle::create(...$intermediates));
        static::assertSame([], $paths);
    }

    #[Test]
    public function combinatorialExplosionIsRejected()
    {
        // five levels of three interchangeable issuers each, that is 243 paths
        $intermediates = [];
        $issuerKeyId = 'root-key-id';
        $issuerName = 'cn=Root';
        for ($level = 5; $level > 0; --$level) {
            for ($choice = 0; $choice < 3; ++$choice) {
                $intermediates[] = self::createCertificate(
                    "cn=L{$level}",
                    $issuerName,
                    "l{$level}-key-id",
                    $issuerKeyId,
                    1000 + $level * 10 + $choice
                );
            }
            $issuerName = "cn=L{$level}";
            $issuerKeyId = "l{$level}-key-id";
        }
        $target = self::createCertificate('cn=EE', $issuerName, 'ee-key-id', $issuerKeyId, 2000);
        $builder = CertificationPathBuilder::create(CertificateBundle::create(self::$_root));
        $this->expectException(PathBuildingException::class);
        $this->expectExceptionMessage('Too many certification paths.');
        $builder->allPathsToTarget($target, CertificateBundle::create(...$intermediates));
    }

    private static function createCertificate(
        string $subject,
        string $issuer,
        string $keyIdentifier,
        string $authorityKeyIdentifier,
        int $serial
    ): Certificate {
        $tbs = TBSCertificate::create(
            Name::fromString($subject),
            self::$_key->publicKeyInfo(),
            Name::fromString($issuer),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withSerialNumber($serial)
            ->withAdditionalExtensions(
                BasicConstraintsExtension::create(true, true),
                SubjectKeyIdentifierExtension::create(false, $keyIdentifier),
                AuthorityKeyIdentifierExtension::create(false, $authorityKeyIdentifier)
            );
        return $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_key);
    }
}
