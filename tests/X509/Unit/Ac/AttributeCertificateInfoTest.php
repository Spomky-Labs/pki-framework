<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use Brick\Math\BigInteger;
use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;
use function mb_strlen;

/**
 * @internal
 */
final class AttributeCertificateInfoTest extends TestCase
{
    final public const ISSUER_DN = 'cn=Issuer';

    private static ?Holder $_holder = null;

    private static ?AttCertIssuer $_issuer = null;

    private static ?AttCertValidityPeriod $_validity = null;

    private static ?Attributes $_attribs = null;

    private static ?Extensions $_extensions = null;

    private static ?OneAsymmetricKey $_privKeyInfo = null;

    public static function setUpBeforeClass(): void
    {
        self::$_holder = Holder::create(
            IssuerSerial::create(GeneralNames::create(DirectoryName::fromDNString(self::ISSUER_DN)), '42')
        );
        self::$_issuer = AttCertIssuer::fromName(Name::fromString(self::ISSUER_DN));
        self::$_validity = AttCertValidityPeriod::fromStrings('2016-04-29 12:00:00', '2016-04-29 13:00:00');
        self::$_attribs = Attributes::fromAttributeValues(
            RoleAttributeValue::create(UniformResourceIdentifier::create('urn:admin'))
        );
        self::$_extensions = Extensions::create(AuthorityKeyIdentifierExtension::create(true, 'test'));
        self::$_privKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_holder = null;
        self::$_issuer = null;
        self::$_validity = null;
        self::$_attribs = null;
        self::$_extensions = null;
        self::$_privKeyInfo = null;
    }

    #[Test]
    public function create(): AttributeCertificateInfo
    {
        $aci = AttributeCertificateInfo::create(self::$_holder, self::$_issuer, self::$_validity, self::$_attribs);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    #[Test]
    public function createWithAll(): AttributeCertificateInfo
    {
        $aci = AttributeCertificateInfo::create(self::$_holder, self::$_issuer, self::$_validity, self::$_attribs);
        $aci = $aci->withSignature(SHA256WithRSAEncryptionAlgorithmIdentifier::create())
            ->withSerialNumber(1)
            ->withExtensions(self::$_extensions)
            ->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    #[Test]
    #[Depends('createWithAll')]
    public function encode(AttributeCertificateInfo $aci): string
    {
        $seq = $aci->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): AttributeCertificateInfo
    {
        $tc = AttributeCertificateInfo::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(AttributeCertificateInfo::class, $tc);
        return $tc;
    }

    #[Test]
    #[Depends('createWithAll')]
    #[Depends('decode')]
    public function recoded(AttributeCertificateInfo $ref, AttributeCertificateInfo $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithAll')]
    public function version(AttributeCertificateInfo $aci)
    {
        static::assertSame(AttributeCertificateInfo::VERSION_2, $aci->version());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function holder(AttributeCertificateInfo $aci)
    {
        static::assertEquals(self::$_holder, $aci->holder());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function issuer(AttributeCertificateInfo $aci)
    {
        static::assertEquals(self::$_issuer, $aci->issuer());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function signature(AttributeCertificateInfo $aci)
    {
        static::assertEquals(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $aci->signature());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function serialNumber(AttributeCertificateInfo $aci)
    {
        static::assertSame('1', $aci->serialNumber());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function validityPeriod(AttributeCertificateInfo $aci)
    {
        static::assertEquals(self::$_validity, $aci->validityPeriod());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function attributes(AttributeCertificateInfo $aci)
    {
        static::assertEquals(self::$_attribs, $aci->attributes());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function issuerUniqueID(AttributeCertificateInfo $aci)
    {
        static::assertSame('uid', $aci->issuerUniqueID()->string());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function extensions(AttributeCertificateInfo $aci)
    {
        static::assertEquals(self::$_extensions, $aci->extensions());
    }

    #[Test]
    #[Depends('create')]
    public function withHolder(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withHolder(self::$_holder);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    #[Test]
    #[Depends('create')]
    public function withIssuer(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withIssuer(self::$_issuer);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    #[Test]
    #[Depends('create')]
    public function withSignature(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    #[Test]
    #[Depends('create')]
    public function withSerial(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withSerialNumber(123);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    #[Test]
    #[Depends('create')]
    public function withRandomSerial(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withRandomSerialNumber(16);
        $bin = BigInteger::of($aci->serialNumber())->toBytes();
        static::assertSame(16, mb_strlen($bin, '8bit'));
    }

    #[Test]
    #[Depends('create')]
    public function withValidity(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withValidity(self::$_validity);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    #[Test]
    #[Depends('create')]
    public function withAttributes(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withAttributes(self::$_attribs);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    #[Test]
    #[Depends('create')]
    public function withIssuerUniqueID(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withIssuerUniqueID(UniqueIdentifier::fromString('id'));
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    #[Test]
    #[Depends('create')]
    public function withExtensions(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withExtensions(self::$_extensions);
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    #[Test]
    #[Depends('create')]
    public function withAdditionalExtensions(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withAdditionalExtensions(AuthorityKeyIdentifierExtension::create(true, 'test'));
        static::assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    #[Test]
    #[Depends('createWithAll')]
    public function decodeInvalidVersion(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $seq = $seq->withReplaced(0, Integer::create(0));
        $this->expectException(UnexpectedValueException::class);
        AttributeCertificateInfo::fromASN1($seq);
    }

    #[Test]
    #[Depends('create')]
    public function noSignatureFail(AttributeCertificateInfo $aci)
    {
        $this->expectException(LogicException::class);
        $aci->signature();
    }

    #[Test]
    #[Depends('create')]
    public function noSerialFail(AttributeCertificateInfo $aci)
    {
        $this->expectException(LogicException::class);
        $aci->serialNumber();
    }

    #[Test]
    #[Depends('create')]
    public function noIssuerUniqueIdFail(AttributeCertificateInfo $aci)
    {
        $this->expectException(LogicException::class);
        $aci->issuerUniqueID();
    }

    #[Test]
    #[Depends('create')]
    public function sign(AttributeCertificateInfo $aci)
    {
        $ac = $aci->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privKeyInfo);
        static::assertInstanceOf(AttributeCertificate::class, $ac);
    }

    #[Test]
    #[Depends('createWithAll')]
    public function invalidAlgoFail(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $algo = GenericAlgorithmIdentifier::create('1.3.6.1.3');
        $seq = $seq->withReplaced(3, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        AttributeCertificateInfo::fromASN1($seq);
    }
}
