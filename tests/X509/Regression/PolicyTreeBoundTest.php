<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePoliciesExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappings\PolicyMapping;
use SpomkyLabs\Pki\X509\Certificate\Extension\PolicyMappingsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * RFC 5280 places no bound on the valid policy tree, and the tree grows multiplicatively: a policy mapping gives a
 * node an expected policy set of the size the issuing certificate chose, and the next certificate's anyPolicy then
 * creates one child per expected policy per node. Under a megabyte of certificate policies reached a gigabyte of
 * nodes, in a path whose every signature verifies, which is the situation a root delegating a sub-CA to a third
 * party is in.
 *
 * @internal
 */
final class PolicyTreeBoundTest extends TestCase
{
    private const OID_PREFIX = '1.3.6.1.4.1.45710.9.';

    private static ?PrivateKeyInfo $rootKey = null;

    private static ?PrivateKeyInfo $caKey = null;

    private static ?PrivateKeyInfo $leafKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$rootKey = self::key('acme-ca-rsa');
        self::$caKey = self::key('acme-interm-rsa');
        self::$leafKey = self::key('acme-rsa');
    }

    public static function tearDownAfterClass(): void
    {
        self::$rootKey = null;
        self::$caKey = null;
        self::$leafKey = null;
    }

    #[Test]
    public function aTreeThatGrowsPastTheBoundIsRefused(): void
    {
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('Certificate policy tree is too large.');
        self::validate(48, 2);
    }

    #[Test]
    public function anOrdinaryPolicyMappingPathStillValidates(): void
    {
        static::assertInstanceOf(PathValidationResult::class, self::validate(2, 1));
    }

    private static function validate(int $fanOut, int $attackerCAs): PathValidationResult
    {
        $mappings = [];
        $policies = [];
        for ($j = 1; $j <= $fanOut; ++$j) {
            $policies[] = PolicyInformation::create(self::OID_PREFIX . $j);
            for ($k = 1; $k <= $fanOut; ++$k) {
                $mappings[] = PolicyMapping::create(self::OID_PREFIX . $j, self::OID_PREFIX . $k);
            }
        }

        $root = self::certificate('cn=Root', self::$rootKey, null, self::$rootKey, Extensions::create(
            BasicConstraintsExtension::create(true, true),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN),
            CertificatePoliciesExtension::create(false, ...$policies)
        ));

        $certificates = [$root];
        $previousName = 'cn=Root';
        $previousKey = self::$rootKey;
        for ($i = 0; $i < $attackerCAs; ++$i) {
            $name = 'cn=CA' . $i;
            $certificates[] = self::certificate($name, self::$caKey, $previousName, $previousKey, Extensions::create(
                BasicConstraintsExtension::create(true, true),
                KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN),
                CertificatePoliciesExtension::create(false, PolicyInformation::create(
                    PolicyInformation::OID_ANY_POLICY
                )),
                PolicyMappingsExtension::create(true, ...$mappings)
            ));
            $previousName = $name;
            $previousKey = self::$caKey;
        }
        $certificates[] = self::certificate('cn=EE', self::$leafKey, $previousName, $previousKey, Extensions::create(
            BasicConstraintsExtension::create(true, false),
            CertificatePoliciesExtension::create(false, ...$policies)
        ));

        return CertificationPath::create(...$certificates)->validate(
            PathValidationConfig::create(new DateTimeImmutable('2026-01-01'), 10)->withTrustAnchor($root)
        );
    }

    private static function certificate(
        string $subject,
        PrivateKeyInfo $subjectKey,
        ?string $issuer,
        PrivateKeyInfo $issuerKey,
        Extensions $extensions
    ): Certificate {
        return TBSCertificate::create(
            Name::fromString($subject),
            $subjectKey->publicKeyInfo(),
            Name::fromString($issuer ?? $subject),
            Validity::fromStrings('2024-01-01 12:00:00 UTC', '2034-01-01 12:00:00 UTC')
        )
            ->withExtensions($extensions)
            ->withSerialNumber(1)
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $issuerKey);
    }

    private static function key(string $name): PrivateKeyInfo
    {
        return PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/' . $name . '.pem'))
            ->privateKeyInfo();
    }
}
