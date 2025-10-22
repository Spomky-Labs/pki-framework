<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\Ac;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class IssuerSerialTest extends TestCase
{
    private static ?Certificate $_cert = null;

    private static ?OneAsymmetricKey $_privKey = null;

    public static function setUpBeforeClass(): void
    {
        self::$_cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        self::$_privKey = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_cert = null;
        self::$_privKey = null;
    }

    #[Test]
    public function fromCertificate(): IssuerSerial
    {
        $is = IssuerSerial::fromPKC(self::$_cert);
        static::assertInstanceOf(IssuerSerial::class, $is);
        return $is;
    }

    #[Test]
    #[Depends('fromCertificate')]
    public function issuer(IssuerSerial $is)
    {
        static::assertEquals(self::$_cert->tbsCertificate()->issuer(), $is->issuer()->firstDN());
    }

    #[Test]
    #[Depends('fromCertificate')]
    public function serial(IssuerSerial $is)
    {
        static::assertSame(self::$_cert->tbsCertificate()->serialNumber(), $is->serial());
    }

    #[Test]
    public function identifiesPKCSerialMismatch()
    {
        $is = IssuerSerial::create(GeneralNames::create(
            DirectoryName::create(self::$_cert->tbsCertificate()->issuer())
        ), '1');
        static::assertFalse($is->identifiesPKC(self::$_cert));
    }

    #[Test]
    public function identifiesPKCWithIssuerUID()
    {
        $tbs = TBSCertificate::create(
            Name::fromString('cn=Sub'),
            self::$_privKey->publicKeyInfo(),
            Name::fromString('cn=Iss'),
            Validity::fromStrings('now', 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        $cert = $tbs->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privKey);
        $is = IssuerSerial::fromPKC($cert);
        static::assertTrue($is->identifiesPKC($cert));
    }

    #[Test]
    public function identifiesPKCIssuerUIDMismatch()
    {
        $issuer = Name::fromString('cn=Iss');
        $tbs = TBSCertificate::create(
            Name::fromString('cn=Sub'),
            self::$_privKey->publicKeyInfo(),
            $issuer,
            Validity::fromStrings('now', 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        $cert = $tbs->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privKey);
        $is = IssuerSerial::create(
            GeneralNames::create(DirectoryName::create($issuer)),
            $cert->tbsCertificate()
                ->serialNumber(),
            UniqueIdentifier::fromString('fail')
        );
        static::assertFalse($is->identifiesPKC($cert));
    }

    #[Test]
    public function identifiesPKCNoUID()
    {
        $is = IssuerSerial::create(
            GeneralNames::create(DirectoryName::create(self::$_cert->tbsCertificate()->issuer())),
            self::$_cert->tbsCertificate()->serialNumber(),
            UniqueIdentifier::fromString('uid')
        );
        static::assertFalse($is->identifiesPKC(self::$_cert));
    }
}
