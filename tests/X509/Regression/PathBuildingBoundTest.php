<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use function count;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathBuildingException;
use SpomkyLabs\Pki\X509\CertificationPath\PathBuilding\CertificationPathBuilder;

/**
 * assertPathCount() was called only inside the loop that appends produced paths, so a sub-call returning no path
 * left the count untouched even though it had already explored its whole subtree. A bundle of mutually issuing
 * certificates that chains to no trust anchor is exactly that shape, and it made the recursion enumerate every
 * ordered sequence up to MAX_PATH_LENGTH: eleven certificates, under seven kilobytes, cost over two minutes of CPU
 * with memory staying flat.
 *
 * @internal
 */
final class PathBuildingBoundTest extends TestCase
{
    private static ?PrivateKeyInfo $rootKey = null;

    private static ?PrivateKeyInfo $keyA = null;

    private static ?PrivateKeyInfo $keyB = null;

    public static function setUpBeforeClass(): void
    {
        self::$rootKey = self::key('acme-ca-rsa');
        self::$keyA = self::key('acme-interm-rsa');
        self::$keyB = self::key('acme-rsa');
    }

    public static function tearDownAfterClass(): void
    {
        self::$rootKey = null;
        self::$keyA = null;
        self::$keyB = null;
    }

    #[Test]
    public function aBundleThatReachesNoAnchorIsBounded(): void
    {
        $anchor = self::certificate('cn=Unreachable Root', self::$rootKey, null, self::$rootKey, true);
        $bundle = [];
        // one shared key identifier, two alternating subject names, none of them self-issued
        for ($i = 0; $i < 12; ++$i) {
            $bundle[] = self::certificate(
                'cn=A' . ($i % 2),
                $i % 2 === 1 ? self::$keyB : self::$keyA,
                'cn=A' . (($i + 1) % 2),
                $i % 2 === 1 ? self::$keyA : self::$keyB,
                true,
                $i + 1
            );
        }

        $this->expectException(PathBuildingException::class);
        $this->expectExceptionMessage('Too many certificates examined');
        CertificationPath::toTarget($bundle[0], CertificateBundle::create($anchor), CertificateBundle::create(
            ...$bundle
        ));
    }

    #[Test]
    public function anOrdinaryPathIsStillBuilt(): void
    {
        $root = self::certificate('cn=Root', self::$rootKey, null, self::$rootKey, true);
        $intermediate = self::certificate('cn=Intermediate', self::$keyA, 'cn=Root', self::$rootKey, true);
        $leaf = self::certificate('cn=EE', self::$keyB, 'cn=Intermediate', self::$keyA, false);

        $path = CertificationPath::toTarget(
            $leaf,
            CertificateBundle::create($root),
            CertificateBundle::create($intermediate)
        );

        static::assertCount(3, $path);
        static::assertSame('cn=EE', $path->endEntityCertificate()->tbsCertificate()->subject()->toString());
    }

    #[Test]
    public function aShortBundleIsUnaffected(): void
    {
        $root = self::certificate('cn=Root', self::$rootKey, null, self::$rootKey, true);
        $intermediate = self::certificate('cn=Intermediate', self::$keyA, 'cn=Root', self::$rootKey, true);
        $leaf = self::certificate('cn=EE', self::$keyB, 'cn=Intermediate', self::$keyA, false);

        $paths = CertificationPathBuilder::create(
            CertificateBundle::create($root)
        )->allPathsToTarget($leaf, CertificateBundle::create($intermediate));

        static::assertGreaterThan(0, count($paths));
    }

    private static function key(string $name): PrivateKeyInfo
    {
        return PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/' . $name . '.pem'))
            ->privateKeyInfo();
    }

    private static function certificate(
        string $subject,
        PrivateKeyInfo $subjectKey,
        ?string $issuer,
        PrivateKeyInfo $issuerKey,
        bool $ca,
        int $serial = 1
    ): Certificate {
        $keyId = str_repeat("\x11", 20);
        $extensions = Extensions::create(
            BasicConstraintsExtension::create(true, $ca),
            SubjectKeyIdentifierExtension::create(false, $keyId),
            AuthorityKeyIdentifierExtension::create(false, $keyId)
        );
        if ($ca) {
            $extensions = $extensions->withExtensions(
                KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN)
            );
        }
        $tbs = TBSCertificate::create(
            Name::fromString($subject),
            $subjectKey->publicKeyInfo(),
            Name::fromString($issuer ?? $subject),
            Validity::fromStrings('2024-01-01 12:00:00 UTC', '2034-01-01 12:00:00 UTC')
        )
            ->withExtensions($extensions)
            ->withSerialNumber($serial);

        return $tbs->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $issuerKey);
    }
}
