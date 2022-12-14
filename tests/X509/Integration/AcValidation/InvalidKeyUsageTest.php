<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcValidation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoEncoding\PEMBundle;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
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
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\Exception\X509ValidationException;

/**
 * @internal
 */
final class InvalidKeyUsageTest extends TestCase
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
        $issuer_ca = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-ecdsa.pem'));
        $issuer_ca_pk = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-ec.pem'));
        $issuer_pk = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'));
        // create issuer certificate
        $tbs = TBSCertificate::create(
            Name::fromString('cn=AC CA'),
            $issuer_pk->publicKeyInfo(),
            Name::create(),
            Validity::fromStrings('now', 'now + 1 hour')
        );
        $tbs = $tbs->withIssuerCertificate($issuer_ca);
        $tbs = $tbs->withAdditionalExtensions(KeyUsageExtension::create(true, 0));
        $issuer = $tbs->sign(ECDSAWithSHA512AlgorithmIdentifier::create(), $issuer_ca_pk);
        self::$_holderPath = CertificationPath::fromTrustAnchorToTarget($root_ca, $holder, $interms);
        self::$_issuerPath = CertificationPath::fromTrustAnchorToTarget($root_ca, $issuer, $interms);
        $aci = AttributeCertificateInfo::create(
            Holder::fromPKC($holder),
            AttCertIssuer::fromPKC($issuer),
            AttCertValidityPeriod::fromStrings('now', 'now + 1 hour'),
            Attributes::create()
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
    public function validate()
    {
        $config = ACValidationConfig::create(self::$_holderPath, self::$_issuerPath);
        $validator = ACValidator::create(self::$_ac, $config);
        $this->expectException(X509ValidationException::class);
        $validator->validate();
    }
}
