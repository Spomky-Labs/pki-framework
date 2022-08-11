<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Certificate;

use Brick\Math\BigInteger;
use LogicException;
use function mb_strlen;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
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

/**
 * @internal
 */
final class TBSCertificateTest extends TestCase
{
    private static $_subject;

    private static $_privateKeyInfo;

    private static $_issuer;

    private static $_validity;

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

    /**
     * @test
     */
    public function create()
    {
        $tc = new TBSCertificate(
            self::$_subject,
            self::$_privateKeyInfo->publicKeyInfo(),
            self::$_issuer,
            self::$_validity
        );
        static::assertInstanceOf(TBSCertificate::class, $tc);
        return $tc;
    }

    /**
     * @test
     */
    public function createWithAll()
    {
        $tc = new TBSCertificate(
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
            ->withAdditionalExtensions(new BasicConstraintsExtension(true, false));
        static::assertInstanceOf(TBSCertificate::class, $tc);
        return $tc;
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function encodeWithAll(TBSCertificate $tc)
    {
        $seq = $tc->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encodeWithAll
     *
     * @param string $der
     *
     * @test
     */
    public function decodeWithAll($der)
    {
        $tc = TBSCertificate::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(TBSCertificate::class, $tc);
        return $tc;
    }

    /**
     * @depends createWithAll
     * @depends decodeWithAll
     *
     * @test
     */
    public function recoded(TBSCertificate $ref, TBSCertificate $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function version(TBSCertificate $tc)
    {
        static::assertEquals(TBSCertificate::VERSION_3, $tc->version());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function serialNumber(TBSCertificate $tc)
    {
        static::assertEquals(1, $tc->serialNumber());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function signature(TBSCertificate $tc)
    {
        static::assertEquals(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), $tc->signature());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function issuer(TBSCertificate $tc)
    {
        static::assertEquals(self::$_issuer, $tc->issuer());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function validity(TBSCertificate $tc)
    {
        static::assertEquals(self::$_validity, $tc->validity());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function subject(TBSCertificate $tc)
    {
        static::assertEquals(self::$_subject, $tc->subject());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function subjectPKI(TBSCertificate $tc)
    {
        static::assertEquals(self::$_privateKeyInfo->publicKeyInfo(), $tc->subjectPublicKeyInfo());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function issuerUniqueID(TBSCertificate $tc)
    {
        static::assertEquals('issuer', $tc->issuerUniqueID()->string());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function subjectUniqueID(TBSCertificate $tc)
    {
        static::assertEquals('subject', $tc->subjectUniqueID()->string());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function extensions(TBSCertificate $tc)
    {
        static::assertInstanceOf(Extensions::class, $tc->extensions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withVersion(TBSCertificate $tc)
    {
        $tc = $tc->withVersion(TBSCertificate::VERSION_1);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSerialNumber(TBSCertificate $tc)
    {
        $tc = $tc->withSerialNumber(123);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withRandomSerialNumber(TBSCertificate $tc)
    {
        $tc = $tc->withRandomSerialNumber(16);
        $bin = BigInteger::of($tc->serialNumber())->toBytes();
        static::assertEquals(16, mb_strlen($bin, '8bit'));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSignature(TBSCertificate $tc)
    {
        $tc = $tc->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withIssuer(TBSCertificate $tc)
    {
        $tc = $tc->withIssuer(self::$_issuer);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withValidity(TBSCertificate $tc)
    {
        $tc = $tc->withValidity(self::$_validity);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSubject(TBSCertificate $tc)
    {
        $tc = $tc->withSubject(self::$_subject);
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSubjectPublicKeyInfo(TBSCertificate $tc)
    {
        $tc = $tc->withSubjectPublicKeyInfo(self::$_privateKeyInfo->publicKeyInfo());
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withIssuerUniqueID(TBSCertificate $tc)
    {
        $tc = $tc->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSubjectUniqueID(TBSCertificate $tc)
    {
        $tc = $tc->withSubjectUniqueID(UniqueIdentifier::fromString('uid'));
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withExtensions(TBSCertificate $tc)
    {
        $tc = $tc->withExtensions(new Extensions());
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAdditionalExtensions(TBSCertificate $tc)
    {
        $tc = $tc->withAdditionalExtensions(new UnknownExtension('1.3.6.1.3', false, NullType::create()));
        static::assertInstanceOf(TBSCertificate::class, $tc);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noVersionFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->version();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noSerialFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->serialNumber();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noSignatureFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->signature();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noIssuerUniqueIDFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->issuerUniqueID();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noSubjectUniqueIDFail(TBSCertificate $tc)
    {
        $this->expectException(LogicException::class);
        $tc->subjectUniqueID();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function sign(TBSCertificate $tc)
    {
        $cert = $tc->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertInstanceOf(Certificate::class, $cert);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function decodeVersion1(TBSCertificate $tc)
    {
        $tc = $tc->withVersion(TBSCertificate::VERSION_1)
            ->withSerialNumber(1)
            ->withSignature(SHA1WithRSAEncryptionAlgorithmIdentifier::create());
        $seq = $tc->toASN1();
        $tbs_cert = TBSCertificate::fromASN1($seq);
        static::assertInstanceOf(TBSCertificate::class, $tbs_cert);
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function invalidAlgoFail(TBSCertificate $tc)
    {
        $seq = $tc->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $seq = $seq->withReplaced(2, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        TBSCertificate::fromASN1($seq);
    }
}
