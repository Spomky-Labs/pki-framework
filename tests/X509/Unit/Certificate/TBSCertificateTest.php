<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use Brick\Math\BigInteger;
use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\UniqueIdentifier;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use UnexpectedValueException;
use function mb_strlen;

/**
 * @internal
 */
final class TBSCertificateTest extends TestCase
{
    private static ?Name $_subject = null;

    private static ?OneAsymmetricKey $_privateKeyInfo = null;

    private static ?Name $_issuer = null;

    private static ?Validity $_validity = null;

    public static function setUpBeforeClass(): void
    {
        self::$_subject = Name::fromString('cn=Subject');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        self::$_issuer = Name::fromString('cn=Issuer');
        self::$_validity = Validity::fromStrings('2016-04-26 12:00:00', '2016-04-26 13:00:00');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_subject = null;
        self::$_privateKeyInfo = null;
        self::$_issuer = null;
        self::$_validity = null;
    }

    #[Test]
    public function create(): TBSCertificate
    {
        $tc = TBSCertificate::create(
            self::$_subject,
            self::$_privateKeyInfo->publicKeyInfo(),
            self::$_issuer,
            self::$_validity
        );
        static::assertInstanceOf(TBSCertificate::class, $tc);
        return $tc;
    }

    #[Test]
    public function createWithAll(): TBSCertificate
    {
        $tc = TBSCertificate::create(
            self::$_subject,
            self::$_privateKeyInfo->publicKeyInfo(),
            self::$_issuer,
            self::$_validity
        );
        $tc = $tc->withVersion(TBSCertificate::VERSION_3)
            ->withSerialNumber(1)
            ->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create())
            ->withIssuerUniqueID(UniqueIdentifier::fromString('issuer'))
            ->withSubjectUniqueID(UniqueIdentifier::fromString('subject'))
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, false));
        static::assertInstanceOf(TBSCertificate::class, $tc);
        return $tc;
    }

    #[Test]
    #[Depends('createWithAll')]
    public function encodeWithAll(TBSCertificate $tc): string
    {
        $seq = $tc->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encodeWithAll')]
    public function decodeWithAll($der): TBSCertificate
    {
        $tc = TBSCertificate::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(TBSCertificate::class, $tc);
        return $tc;
    }

    #[Test]
    #[Depends('createWithAll')]
    #[Depends('decodeWithAll')]
    public function recoded(TBSCertificate $ref, TBSCertificate $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('createWithAll')]
    public function version(TBSCertificate $tc)
    {
        static::assertSame(TBSCertificate::VERSION_3, $tc->version());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function serialNumber(TBSCertificate $tc)
    {
        static::assertSame('1', $tc->serialNumber());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function signature(TBSCertificate $tc)
    {
        static::assertEquals(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), $tc->signature());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function issuer(TBSCertificate $tc)
    {
        static::assertEquals(self::$_issuer, $tc->issuer());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function validity(TBSCertificate $tc)
    {
        static::assertEquals(self::$_validity, $tc->validity());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function subject(TBSCertificate $tc)
    {
        static::assertEquals(self::$_subject, $tc->subject());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function subjectPKI(TBSCertificate $tc)
    {
        static::assertEquals(self::$_privateKeyInfo->publicKeyInfo(), $tc->subjectPublicKeyInfo());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function issuerUniqueID(TBSCertificate $tc)
    {
        static::assertSame('issuer', $tc->issuerUniqueID()->string());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function subjectUniqueID(TBSCertificate $tc)
    {
        static::assertSame('subject', $tc->subjectUniqueID()->string());
    }

    #[Test]
    #[Depends('createWithAll')]
    public function extensions(TBSCertificate $tc)
    {
        static::assertInstanceOf(Extensions::class, $tc->extensions());
    }

    #[Test]
    #[Depends('create')]
    public function withVersion(TBSCertificate $tc)
    {
        $tc = $tc->withVersion(TBSCertificate::VERSION_1);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withSerialNumber(TBSCertificate $tc)
    {
        $tc = $tc->withSerialNumber(123);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withRandomSerialNumber(TBSCertificate $tc)
    {
        $tc = $tc->withRandomSerialNumber(16);
        $bin = BigInteger::of($tc->serialNumber())->toBytes();
        static::assertSame(16, mb_strlen($bin, '8bit'));
    }

    #[Test]
    #[Depends('create')]
    public function withSignature(TBSCertificate $tc)
    {
        $tc = $tc->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withIssuer(TBSCertificate $tc)
    {
        $tc = $tc->withIssuer(self::$_issuer);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withValidity(TBSCertificate $tc)
    {
        $tc = $tc->withValidity(self::$_validity);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withSubject(TBSCertificate $tc)
    {
        $tc = $tc->withSubject(self::$_subject);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withSubjectPublicKeyInfo(TBSCertificate $tc)
    {
        $tc = $tc->withSubjectPublicKeyInfo(self::$_privateKeyInfo->publicKeyInfo());
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withIssuerUniqueID(TBSCertificate $tc)
    {
        $tc = $tc->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withSubjectUniqueID(TBSCertificate $tc)
    {
        $tc = $tc->withSubjectUniqueID(UniqueIdentifier::fromString('uid'));
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withExtensions(TBSCertificate $tc)
    {
        $tc = $tc->withExtensions(Extensions::create());
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function withAdditionalExtensions(TBSCertificate $tc)
    {
        $tc = $tc->withAdditionalExtensions(UnknownExtension::create('1.3.6.1.3', false, NullType::create()));
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    #[Test]
    #[Depends('create')]
    public function noVersionFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->version();
    }

    #[Test]
    #[Depends('create')]
    public function noSerialFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->serialNumber();
    }

    #[Test]
    #[Depends('create')]
    public function noSignatureFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->signature();
    }

    #[Test]
    #[Depends('create')]
    public function noIssuerUniqueIDFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->issuerUniqueID();
    }

    #[Test]
    #[Depends('create')]
    public function noSubjectUniqueIDFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->subjectUniqueID();
    }

    #[Test]
    #[Depends('create')]
    public function sign(TBSCertificate $tc)
    {
        $cert = $tc->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertInstanceOf(Certificate::class, $cert);
    }

    #[Test]
    #[Depends('create')]
    public function decodeVersion1(TBSCertificate $tc)
    {
        $tc = $tc->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(1)
            ->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        $seq = $tc->toASN1();
        $tbs_cert = TBSCertificate::fromASN1($seq);
        static::assertInstanceOf(TBSCertificate::class, $tbs_cert);
    }

    #[Test]
    #[Depends('createWithAll')]
    public function invalidAlgoFail(TBSCertificate $tc)
    {
        $seq = $tc->toASN1();
        $algo = GenericAlgorithmIdentifier::create('1.3.6.1.3');
        $seq = $seq->withReplaced(2, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        TBSCertificate::fromASN1($seq);
    }
}
