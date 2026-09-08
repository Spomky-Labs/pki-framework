<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\PathValidation;

use function count;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtree;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraints\GeneralSubtrees;
use SpomkyLabs\Pki\X509\Certificate\Extension\NameConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\RegisteredID;
use SpomkyLabs\Pki\X509\GeneralName\RFC822Name;

/**
 * Covers the enforcement of the name constraints extension during certification path validation.
 *
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.3
 * @see https://tools.ietf.org/html/rfc5280#section-6.1.4
 *
 * @internal
 */
final class NameConstraintsEnforcementTest extends TestCase
{
    public const CA_NAME = 'cn=CA';

    public const INTERM_NAME = 'cn=Interm';

    private static ?PrivateKeyInfo $_caKey = null;

    private static ?PrivateKeyInfo $_intermKey = null;

    private static ?PrivateKeyInfo $_certKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem')
        )->privateKeyInfo();
        self::$_intermKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem')
        )->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem')
        )->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_intermKey = null;
        self::$_certKey = null;
    }

    #[Test]
    public function permittedDNSNameViolationIsRejected(): void
    {
        $path = $this->path(
            self::permitted(DNSName::create('example.com')),
            null,
            'cn=EE',
            SubjectAlternativeNameExtension::create(false, GeneralNames::create(DNSName::create('evil.attacker.tld')))
        );
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage("Name 'evil.attacker.tld' is not within the permitted subtrees.");
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function permittedDNSNameIsAccepted(): void
    {
        $path = $this->path(
            self::permitted(DNSName::create('example.com')),
            null,
            'cn=EE',
            SubjectAlternativeNameExtension::create(false, GeneralNames::create(DNSName::create('www.example.com')))
        );
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function excludedDNSNameIsRejected(): void
    {
        $path = $this->path(
            self::excluded(DNSName::create('bad.example.com')),
            null,
            'cn=EE',
            SubjectAlternativeNameExtension::create(
                false,
                GeneralNames::create(DNSName::create('www.bad.example.com'))
            )
        );
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage("Name 'www.bad.example.com' is within an excluded subtree.");
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function nameOutsideExcludedSubtreeIsAccepted(): void
    {
        $path = $this->path(
            self::excluded(DNSName::create('bad.example.com')),
            null,
            'cn=EE',
            SubjectAlternativeNameExtension::create(
                false,
                GeneralNames::create(DNSName::create('www.good.example.com'))
            )
        );
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function subjectOutsidePermittedDirectoryNameIsRejected(): void
    {
        $path = $this->path(null, self::permitted(DirectoryName::fromDNString('c=FI')), 'cn=EE,c=SE');
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('is not within the permitted subtrees.');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function subjectWithinPermittedDirectoryNameIsAccepted(): void
    {
        $path = $this->path(null, self::permitted(DirectoryName::fromDNString('c=FI')), 'cn=EE,c=FI');
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function intermediateOutsidePermittedDirectoryNameIsRejected(): void
    {
        // the constraints of the issuing CA apply to the intermediate certificate itself
        $path = $this->path(self::permitted(DirectoryName::fromDNString('c=FI')), null, 'cn=EE,c=FI');
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage("Name 'cn=Interm' is not within the permitted subtrees.");
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function unconstrainedNameTypeIsAccepted(): void
    {
        // only dNSName is constrained, so the subject and the e-mail address are unrestricted
        $path = $this->path(
            self::permitted(DNSName::create('example.com')),
            null,
            'cn=EE,c=SE',
            SubjectAlternativeNameExtension::create(false, GeneralNames::create(RFC822Name::create('bob@evil.tld')))
        );
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function emptySubjectIsNotCheckedAgainstDirectoryNameConstraints(): void
    {
        // a certificate with an empty subject carries a critical subjectAltName, which the validator does not
        // process on its own and which therefore has to be declared by the application
        $path = $this->path(
            null,
            self::permitted(DirectoryName::fromDNString('c=FI')),
            '',
            SubjectAlternativeNameExtension::create(true, GeneralNames::create(DNSName::create('www.example.com')))
        );
        $config = PathValidationConfig::create(new DateTimeImmutable(), 3)
            ->withAdditionalCriticalExtensions(Extension::OID_SUBJECT_ALT_NAME);
        static::assertInstanceOf(PathValidationResult::class, $path->validate($config));
    }

    #[Test]
    public function permittedSubtreesOfTheWholePathAreIntersected(): void
    {
        $path = $this->path(
            self::permitted(DNSName::create('example.com')),
            self::permitted(DNSName::create('sales.example.com')),
            'cn=EE',
            SubjectAlternativeNameExtension::create(
                false,
                GeneralNames::create(DNSName::create('support.example.com'))
            )
        );
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage("Name 'support.example.com' is not within the permitted subtrees.");
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function nameWithinEveryPermittedSubtreeIsAccepted(): void
    {
        $path = $this->path(
            self::permitted(DNSName::create('example.com')),
            self::permitted(DNSName::create('sales.example.com')),
            'cn=EE',
            SubjectAlternativeNameExtension::create(
                false,
                GeneralNames::create(DNSName::create('www.sales.example.com'))
            )
        );
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function excludedSubtreesOfTheWholePathAreUnited(): void
    {
        $path = $this->path(
            self::excluded(DNSName::create('one.example.com')),
            self::excluded(DNSName::create('two.example.com')),
            'cn=EE',
            SubjectAlternativeNameExtension::create(false, GeneralNames::create(DNSName::create('one.example.com')))
        );
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage("Name 'one.example.com' is within an excluded subtree.");
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function legacyEmailAddressInSubjectIsCheckedWhenNoSubjectAltNameIsPresent(): void
    {
        $path = $this->path(self::permitted(RFC822Name::create('example.com')), null, 'email=bob@evil.tld,cn=EE');
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage("Name 'bob@evil.tld' is not within the permitted subtrees.");
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function legacyEmailAddressWithinPermittedSubtreeIsAccepted(): void
    {
        $path = $this->path(self::permitted(RFC822Name::create('example.com')), null, 'email=bob@example.com,cn=EE');
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function legacyEmailAddressIsIgnoredWhenSubjectAltNameIsPresent(): void
    {
        // RFC 5280 4.2.1.10 submits the subject attribute only for a certificate without subjectAltName
        $path = $this->path(
            self::permitted(RFC822Name::create('example.com')),
            null,
            'email=bob@evil.tld,cn=EE',
            SubjectAlternativeNameExtension::create(
                false,
                GeneralNames::create(RFC822Name::create('bob@example.com'))
            )
        );
        static::assertInstanceOf(
            PathValidationResult::class,
            $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3))
        );
    }

    #[Test]
    public function unsupportedConstraintTypeIsRejected(): void
    {
        $path = $this->path(self::permitted(RegisteredID::create('1.3.6.1.3.1')), null, 'cn=EE');
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('type ' . GeneralName::TAG_REGISTERED_ID . ' is not supported.');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    #[Test]
    public function emptyNameConstraintsExtensionIsRejected(): void
    {
        $path = $this->path(NameConstraintsExtension::create(true), null, 'cn=EE');
        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('Name constraints extension must contain at least one subtree.');
        $path->validate(PathValidationConfig::create(new DateTimeImmutable(), 3));
    }

    private static function permitted(GeneralName $base): NameConstraintsExtension
    {
        return NameConstraintsExtension::create(true, GeneralSubtrees::create(GeneralSubtree::create($base)));
    }

    private static function excluded(GeneralName $base): NameConstraintsExtension
    {
        return NameConstraintsExtension::create(
            true,
            null,
            GeneralSubtrees::create(GeneralSubtree::create($base))
        );
    }

    /**
     * Build a CA -> intermediate -> end-entity path, each CA optionally carrying a name constraints extension.
     */
    private function path(
        ?NameConstraintsExtension $caConstraints,
        ?NameConstraintsExtension $intermConstraints,
        string $certName,
        ?SubjectAlternativeNameExtension $san = null
    ): CertificationPath {
        $ca = $this->certificate(
            self::CA_NAME,
            self::$_caKey,
            self::CA_NAME,
            self::$_caKey,
            ...array_filter([BasicConstraintsExtension::create(true, true), $caConstraints])
        );
        $interm = $this->certificate(
            self::INTERM_NAME,
            self::$_intermKey,
            self::CA_NAME,
            self::$_caKey,
            ...array_filter([BasicConstraintsExtension::create(true, true), $intermConstraints])
        );
        $cert = $this->certificate(
            $certName,
            self::$_certKey,
            self::INTERM_NAME,
            self::$_intermKey,
            ...array_filter([$san])
        );
        return CertificationPath::create($ca, $interm, $cert);
    }

    private function certificate(
        string $subject,
        PrivateKeyInfo $subjectKey,
        string $issuer,
        PrivateKeyInfo $issuerKey,
        Extension ...$extensions
    ): Certificate {
        $tbs = TBSCertificate::create(
            Name::fromString($subject),
            $subjectKey->publicKeyInfo(),
            Name::fromString($issuer),
            Validity::fromStrings(null, 'now + 1 hour')
        );
        $tbs = $tbs->withVersion(TBSCertificate::VERSION_3);
        if (count($extensions) !== 0) {
            $tbs = $tbs->withAdditionalExtensions(...$extensions);
        }
        return $tbs->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), $issuerKey);
    }
}
