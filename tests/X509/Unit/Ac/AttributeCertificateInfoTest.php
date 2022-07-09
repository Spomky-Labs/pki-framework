<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\X501\ASN1\Name;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\AttributeCertificate\AttCertValidityPeriod;
use Sop\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Sop\X509\AttributeCertificate\AttributeCertificate;
use Sop\X509\AttributeCertificate\AttributeCertificateInfo;
use Sop\X509\AttributeCertificate\Attributes;
use Sop\X509\AttributeCertificate\Holder;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Sop\X509\Certificate\Extensions;
use Sop\X509\Certificate\UniqueIdentifier;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;
use Sop\X509\GeneralName\UniformResourceIdentifier;
use UnexpectedValueException;

/**
 * @internal
 */
final class AttributeCertificateInfoTest extends TestCase
{
    final public const ISSUER_DN = 'cn=Issuer';

    private static $_holder;

    private static $_issuer;

    private static $_validity;

    private static $_attribs;

    private static $_extensions;

    private static $_privKeyInfo;

    public static function setUpBeforeClass(): void
    {
        self::$_holder = new Holder(
            new IssuerSerial(new GeneralNames(DirectoryName::fromDNString(self::ISSUER_DN)), 42)
        );
        self::$_issuer = AttCertIssuer::fromName(Name::fromString(self::ISSUER_DN));
        self::$_validity = AttCertValidityPeriod::fromStrings('2016-04-29 12:00:00', '2016-04-29 13:00:00');
        self::$_attribs = Attributes::fromAttributeValues(
            new RoleAttributeValue(new UniformResourceIdentifier('urn:admin'))
        );
        self::$_extensions = new Extensions(new AuthorityKeyIdentifierExtension(true, 'test'));
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

    /**
     * @test
     */
    public function create()
    {
        $aci = new AttributeCertificateInfo(self::$_holder, self::$_issuer, self::$_validity, self::$_attribs);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @test
     */
    public function createWithAll()
    {
        $aci = new AttributeCertificateInfo(self::$_holder, self::$_issuer, self::$_validity, self::$_attribs);
        $aci = $aci->withSignature(new SHA256WithRSAEncryptionAlgorithmIdentifier())
            ->withSerialNumber(1)
            ->withExtensions(self::$_extensions)
            ->withIssuerUniqueID(UniqueIdentifier::fromString('uid'));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function encode(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $der
     *
     * @test
     */
    public function decode($der)
    {
        $tc = AttributeCertificateInfo::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $tc);
        return $tc;
    }

    /**
     * @depends createWithAll
     * @depends decode
     *
     * @test
     */
    public function recoded(AttributeCertificateInfo $ref, AttributeCertificateInfo $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function version(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(AttributeCertificateInfo::VERSION_2, $aci->version());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function holder(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_holder, $aci->holder());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function issuer(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_issuer, $aci->issuer());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function signature(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(new SHA256WithRSAEncryptionAlgorithmIdentifier(), $aci->signature());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function serialNumber(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(1, $aci->serialNumber());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function validityPeriod(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_validity, $aci->validityPeriod());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function attributes(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_attribs, $aci->attributes());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function issuerUniqueID(AttributeCertificateInfo $aci)
    {
        $this->assertEquals('uid', $aci->issuerUniqueID() ->string());
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function extensions(AttributeCertificateInfo $aci)
    {
        $this->assertEquals(self::$_extensions, $aci->extensions());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withHolder(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withHolder(self::$_holder);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withIssuer(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withIssuer(self::$_issuer);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSignature(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withSignature(new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSerial(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withSerialNumber(123);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withRandomSerial(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withRandomSerialNumber(16);
        $bin = gmp_export(gmp_init($aci->serialNumber(), 10), 1);
        $this->assertEquals(16, strlen($bin));
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withValidity(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withValidity(self::$_validity);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAttributes(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withAttributes(self::$_attribs);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withIssuerUniqueID(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withIssuerUniqueID(UniqueIdentifier::fromString('id'));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withExtensions(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withExtensions(self::$_extensions);
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withAdditionalExtensions(AttributeCertificateInfo $aci)
    {
        $aci = $aci->withAdditionalExtensions(new AuthorityKeyIdentifierExtension(true, 'test'));
        $this->assertInstanceOf(AttributeCertificateInfo::class, $aci);
        return $aci;
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function decodeInvalidVersion(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $seq = $seq->withReplaced(0, new Integer(0));
        $this->expectException(UnexpectedValueException::class);
        AttributeCertificateInfo::fromASN1($seq);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noSignatureFail(AttributeCertificateInfo $aci)
    {
        $this->expectException(LogicException::class);
        $aci->signature();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noSerialFail(AttributeCertificateInfo $aci)
    {
        $this->expectException(LogicException::class);
        $aci->serialNumber();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function noIssuerUniqueIdFail(AttributeCertificateInfo $aci)
    {
        $this->expectException(LogicException::class);
        $aci->issuerUniqueID();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function sign(AttributeCertificateInfo $aci)
    {
        $ac = $aci->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_privKeyInfo);
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
    }

    /**
     * @depends createWithAll
     *
     * @test
     */
    public function invalidAlgoFail(AttributeCertificateInfo $aci)
    {
        $seq = $aci->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $seq = $seq->withReplaced(3, $algo->toASN1());
        $this->expectException(UnexpectedValueException::class);
        AttributeCertificateInfo::fromASN1($seq);
    }
}
