<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\PathValidation;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateChain;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * Covers the refusal to anchor validation on the head of a peer-supplied certificate chain.
 *
 * The chain comes from the peer, so its topmost certificate is whatever the peer chose. Validating it against that
 * certificate verifies nothing, and used to succeed silently.
 *
 * @internal
 */
final class PeerSuppliedChainAnchorTest extends TestCase
{
    public const CA_NAME = 'cn=Attacker Root';

    public const CERT_NAME = 'cn=www.example.com';

    private static ?Certificate $ca = null;

    private static ?Certificate $cert = null;

    public static function setUpBeforeClass(): void
    {
        $caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        $certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
        $algo = SHA1WithRSAEncryptionAlgorithmIdentifier::create();
        // a self-signed root the attacker generated, present in no trust store
        $tbs = TBSCertificate::create(
            Name::fromString(self::CA_NAME),
            $caKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withAdditionalExtensions(BasicConstraintsExtension::create(true, true));
        self::$ca = $tbs->sign($algo, $caKey);
        // a leaf that root issues for any name it likes
        $tbs = TBSCertificate::create(
            Name::fromString(self::CERT_NAME),
            $certKey->publicKeyInfo(),
            Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate(self::$ca);
        self::$cert = $tbs->sign($algo, $caKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$ca = null;
        self::$cert = null;
    }

    #[Test]
    public function chainWithoutTrustAnchorIsRejected(): void
    {
        $path = CertificationPath::fromCertificateChain(CertificateChain::create(self::$cert, self::$ca));
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('peer-supplied certificate chain');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function chainConvertedFromCertificateChainIsRejectedToo(): void
    {
        $path = CertificateChain::create(self::$cert, self::$ca)->certificationPath();
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('peer-supplied certificate chain');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function chainWithExplicitTrustAnchorIsValidated(): void
    {
        $path = CertificationPath::fromCertificateChain(CertificateChain::create(self::$cert, self::$ca));
        // the application states which certificate it trusts; here it happens to be that same root
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3)->withTrustAnchor(self::$ca);
        static::assertInstanceOf(PathValidationResult::class, $path->validate($config));
    }

    #[Test]
    public function pathAssembledByTheApplicationStillAnchorsOnItsFirstCertificate(): void
    {
        $path = CertificationPath::create(self::$ca, self::$cert);
        $result = $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
        static::assertInstanceOf(PathValidationResult::class, $result);
    }
}
