<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcValidation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\ACValidationConfig;
use SpomkyLabs\Pki\X509\AttributeCertificate\Validation\ACValidator;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\CertificateBundle;
use SpomkyLabs\Pki\X509\Certificate\Extension\Target\TargetName;
use SpomkyLabs\Pki\X509\Certificate\Extension\TargetInformationExtension;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;

/**
 * @internal
 */
final class PassingTest extends TestCase
{
    private static ?CertificationPath $_holderPath = null;

    private static ?CertificationPath $_issuerPath = null;

    private static ?AttributeCertificate $_ac = null;

    public static function setUpBeforeClass(): void
    {
        $root_ca = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $interms = CertificateBundle::fromPEMBundle(
            PEMBundle::fromFile(TEST_ASSETS_DIR . '/certs/intermediate-bundle.pem')
        );
        $holder = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $issuer = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $issuer_pk = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'));
        self::$_holderPath = CertificationPath::fromTrustAnchorToTarget($root_ca, $holder, $interms);
        self::$_issuerPath = CertificationPath::fromTrustAnchorToTarget($root_ca, $issuer, $interms);
        $aci = AttributeCertificateInfo::create(
            Holder::fromPKC($holder),
            AttCertIssuer::fromPKC($issuer),
            AttCertValidityPeriod::fromStrings('now', 'now + 1 hour'),
            Attributes::create()
        );
        $aci = $aci->withAdditionalExtensions(
            TargetInformationExtension::fromTargets(TargetName::create(DNSName::create('test')))
        );
        self::$_ac = $aci->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $issuer_pk);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_holderPath = null;
        self::$_issuerPath = null;
        self::$_ac = null;
    }

    #[Test]
    public function validate(): void
    {
        $config = ACValidationConfig::create(self::$_holderPath, self::$_issuerPath);
        $config = $config->withTargets(TargetName::create(DNSName::create('test')));
        $validator = ACValidator::create(self::$_ac, $config);
        static::assertInstanceOf(AttributeCertificate::class, $validator->validate());
    }
}
