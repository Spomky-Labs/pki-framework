<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoBridge\Crypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;
use function strval;

/**
 * @internal
 */
final class AttributeCertificateTest extends TestCase
{
    private static ?PEM $_acPem = null;

    private static ?OneAsymmetricKey $_privateKeyInfo = null;

    public static function setUpBeforeClass(): void
    {
        self::$_acPem = PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_acPem = null;
        self::$_privateKeyInfo = null;
    }

    #[Test]
    public function create(): AttributeCertificate
    {
        $holder = Holder::create(
            IssuerSerial::create(GeneralNames::create(DirectoryName::fromDNString('cn=Issuer')), '42')
        );
        $issuer = AttCertIssuer::fromName(Name::fromString('cn=Issuer'));
        $validity = AttCertValidityPeriod::fromStrings('2016-04-29 12:00:00', '2016-04-29 13:00:00');
        $attribs = Attributes::fromAttributeValues(
            RoleAttributeValue::create(UniformResourceIdentifier::create('urn:admin'))
        );
        $acinfo = AttributeCertificateInfo::create($holder, $issuer, $validity, $attribs);
        $algo = SHA256WithRSAEncryptionAlgorithmIdentifier::create();
        $acinfo = $acinfo->withSignature($algo)
            ->withSerialNumber(1);
        $signature = Crypto::getDefault()->sign($acinfo->toASN1()->toDER(), self::$_privateKeyInfo, $algo);
        $ac = AttributeCertificate::create($acinfo, $algo, $signature);
        static::assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    #[Test]
    #[Depends('create')]
    public function encode(AttributeCertificate $ac): string
    {
        $seq = $ac->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    #[Test]
    #[Depends('encode')]
    public function decode(string $der): AttributeCertificate
    {
        $ac = AttributeCertificate::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(AttributeCertificate $ref, AttributeCertificate $new): void
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function attributeCertificateInfo(AttributeCertificate $ac): void
    {
        static::assertInstanceOf(AttributeCertificateInfo::class, $ac->acinfo());
    }

    #[Test]
    #[Depends('create')]
    public function signatureAlgo(AttributeCertificate $ac): void
    {
        static::assertInstanceOf(SignatureAlgorithmIdentifier::class, $ac->signatureAlgorithm());
    }

    #[Test]
    #[Depends('create')]
    public function signatureValue(AttributeCertificate $ac): void
    {
        static::assertInstanceOf(Signature::class, $ac->signatureValue());
    }

    #[Test]
    #[Depends('create')]
    public function verify(AttributeCertificate $ac): void
    {
        $pubkey_info = self::$_privateKeyInfo->publicKeyInfo();
        static::assertTrue($ac->verify($pubkey_info));
    }

    #[Test]
    #[Depends('create')]
    public function invalidAlgoFail(AttributeCertificate $ac): void
    {
        $seq = $ac->toASN1();
        $algo = GenericAlgorithmIdentifier::create('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        AttributeCertificate::fromASN1($seq);
    }

    #[Test]
    public function fromPEM(): AttributeCertificate
    {
        $ac = AttributeCertificate::fromPEM(self::$_acPem);
        static::assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    #[Test]
    #[Depends('fromPEM')]
    public function toPEM(AttributeCertificate $ac): PEM
    {
        $pem = $ac->toPEM();
        static::assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    #[Test]
    #[Depends('toPEM')]
    public function pEMEquals(PEM $pem): void
    {
        static::assertEquals(self::$_acPem, $pem);
    }

    #[Test]
    public function invalidPEMTypeFail(): void
    {
        $this->expectException(UnexpectedValueException::class);
        AttributeCertificate::fromPEM(PEM::create('fail', ''));
    }

    #[Test]
    #[Depends('fromPEM')]
    public function toStringMethod(AttributeCertificate $ac): void
    {
        static::assertIsString(strval($ac));
    }

    #[Test]
    #[Depends('fromPEM')]
    public function isHeldBy(AttributeCertificate $ac): void
    {
        $cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        static::assertTrue($ac->isHeldBy($cert));
    }

    #[Test]
    #[Depends('fromPEM')]
    public function isHeldByFail(AttributeCertificate $ac): void
    {
        $cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        static::assertFalse($ac->isHeldBy($cert));
    }

    #[Test]
    #[Depends('fromPEM')]
    public function isIssuedBy(AttributeCertificate $ac): void
    {
        $cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        static::assertTrue($ac->isIssuedBy($cert));
    }

    #[Test]
    #[Depends('fromPEM')]
    public function isIssuedByFail(AttributeCertificate $ac): void
    {
        $cert = Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        static::assertFalse($ac->isIssuedBy($cert));
    }
}
