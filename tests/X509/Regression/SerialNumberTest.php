<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use Brick\Math\BigInteger;
use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * A constant serial number removes the unpredictability that protects issuance against collision attacks, and
 * breaks CRL revocation, which identifies certificates by the (issuer, serial number) pair.
 *
 * @internal
 */
final class SerialNumberTest extends TestCase
{
    private static ?PrivateKeyInfo $key = null;

    public static function setUpBeforeClass(): void
    {
        self::$key = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))
            ->privateKeyInfo();
    }

    public static function tearDownAfterClass(): void
    {
        self::$key = null;
    }

    #[Test]
    public function signingWithoutASerialNumberNoLongerYieldsZero(): void
    {
        $first = self::sign();
        $second = self::sign();

        static::assertNotSame('0', $first);
        static::assertNotSame($first, $second, 'Serial numbers must not repeat across issuances.');
        static::assertTrue(BigInteger::of($first)->isGreaterThan(0), 'RFC 5280 requires a positive integer.');
    }

    #[Test]
    public function signingWithoutASerialNumberCarriesEnoughEntropy(): void
    {
        // 20 octets with the sign bit cleared span [0, 2^159). A single draw falls below 2^151 once in 256, so
        // assert on the largest of 16 draws instead: that stays under the threshold only with probability 2^-128.
        $largest = BigInteger::zero();
        for ($i = 0; $i < 16; ++$i) {
            $serial = BigInteger::of(self::sign());
            if ($serial->isGreaterThan($largest)) {
                $largest = $serial;
            }
        }

        // Far above the 64 bits the CA/Browser Forum Baseline Requirements ask for.
        static::assertTrue($largest->isGreaterThan(BigInteger::of(2)->power(151)));
    }

    #[Test]
    public function aSmallSizeStillWorksButIsDeprecated(): void
    {
        // Eight octets yield 63 bits once the sign bit is cleared, just short of the requirement. Callers are
        // told, not broken.
        $notices = [];
        set_error_handler(static function (int $errno, string $message) use (&$notices): bool {
            $notices[] = $message;
            return true;
        }, E_USER_DEPRECATED);

        try {
            $serial = self::tbs()->withRandomSerialNumber(8)->serialNumber();
        } finally {
            restore_error_handler();
        }

        static::assertTrue(BigInteger::of($serial)->isGreaterThan(0));
        static::assertCount(1, $notices);
        static::assertStringContainsString('below the 64 bits', $notices[0]);
    }

    #[Test]
    public function theRecommendedSizeIsSilent(): void
    {
        $notices = [];
        set_error_handler(static function (int $errno, string $message) use (&$notices): bool {
            $notices[] = $message;
            return true;
        }, E_USER_DEPRECATED);

        try {
            self::tbs()->withRandomSerialNumber(9);
            self::tbs()->withRandomSerialNumber();
        } finally {
            restore_error_handler();
        }

        static::assertSame([], $notices);
        static::assertSame(9, TBSCertificate::MIN_RANDOM_SERIAL_SIZE);
        static::assertSame(20, TBSCertificate::DEFAULT_RANDOM_SERIAL_SIZE);
    }

    #[Test]
    public function randomSerialNumbersArePositiveAndDistinct(): void
    {
        $seen = [];
        for ($i = 0; $i < 50; ++$i) {
            $serial = self::tbs()->withRandomSerialNumber()->serialNumber();
            static::assertTrue(BigInteger::of($serial)->isGreaterThan(0));
            $seen[$serial] = true;
        }
        static::assertCount(50, $seen);
    }

    #[Test]
    public function attributeCertificatesGetTheSameTreatment(): void
    {
        $first = self::signAttributeCertificate();
        $second = self::signAttributeCertificate();

        static::assertNotSame('0', $first);
        static::assertNotSame($first, $second, 'Serial numbers must not repeat across issuances.');
        static::assertTrue(BigInteger::of($first)->isGreaterThan(0), 'RFC 5280 requires a positive integer.');
        static::assertSame(9, AttributeCertificateInfo::MIN_RANDOM_SERIAL_SIZE);
        static::assertSame(20, AttributeCertificateInfo::DEFAULT_RANDOM_SERIAL_SIZE);
    }

    #[Test]
    public function attributeCertificateRandomSerialNumbersArePositiveAndDistinct(): void
    {
        $seen = [];
        for ($i = 0; $i < 50; ++$i) {
            $serial = self::acinfo()->withRandomSerialNumber()
                ->serialNumber();
            static::assertTrue(BigInteger::of($serial)->isGreaterThan(0));
            $seen[$serial] = true;
        }
        static::assertCount(50, $seen);
    }

    private static function tbs(): TBSCertificate
    {
        return TBSCertificate::create(
            Name::fromString('cn=subject'),
            self::$key->publicKeyInfo(),
            Name::fromString('cn=issuer'),
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        );
    }

    private static function sign(): string
    {
        return self::tbs()
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key)
            ->tbsCertificate()
            ->serialNumber();
    }

    private static function acinfo(): AttributeCertificateInfo
    {
        return AttributeCertificateInfo::create(
            Holder::create(IssuerSerial::create(GeneralNames::create(DirectoryName::fromDNString('cn=issuer')), '42')),
            AttCertIssuer::fromName(Name::fromString('cn=issuer')),
            AttCertValidityPeriod::fromStrings('now - 1 hour', 'now + 1 hour'),
            Attributes::fromAttributeValues(
                RoleAttributeValue::create(UniformResourceIdentifier::create('urn:admin'))
            )
        );
    }

    private static function signAttributeCertificate(): string
    {
        return self::acinfo()
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), self::$key)
            ->acinfo()
            ->serialNumber();
    }
}
