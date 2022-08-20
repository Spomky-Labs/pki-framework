<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\AttributeCertificate\ObjectDigestInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\V2Form;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class V2FormTest extends TestCase
{
    private static $_issuerName;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerName = GeneralNames::create(DirectoryName::fromDNString('cn=Test'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuerName = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $issuer = new V2Form(self::$_issuerName);
        static::assertInstanceOf(AttCertIssuer::class, $issuer);
        return $issuer;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(V2Form $issuer)
    {
        $el = $issuer->toASN1();
        static::assertInstanceOf(ImplicitlyTaggedType::class, $el);
        return $el->toDER();
    }

    /**
     * @depends encode
     *
     * @param string $data
     *
     * @test
     */
    public function decode($data)
    {
        $issuer = V2Form::fromASN1(Element::fromDER($data)->asUnspecified());
        static::assertInstanceOf(V2Form::class, $issuer);
        return $issuer;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(V2Form $ref, V2Form $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function issuerName(V2Form $issuer)
    {
        static::assertEquals(self::$_issuerName, $issuer->issuerName());
    }

    /**
     * @test
     */
    public function noIssuerNameFail()
    {
        $issuer = new V2Form();
        $this->expectException(LogicException::class);
        $issuer->issuerName();
    }

    /**
     * @depends create
     *
     * @test
     */
    public function name(V2Form $issuer)
    {
        static::assertEquals('cn=Test', $issuer->name());
    }

    /**
     * @test
     */
    public function decodeWithAll()
    {
        $iss_ser = new IssuerSerial(self::$_issuerName, 1);
        $odi = new ObjectDigestInfo(
            ObjectDigestInfo::TYPE_PUBLIC_KEY,
            SHA1WithRSAEncryptionAlgorithmIdentifier::create(),
            BitString::create('')
        );
        $el = ImplicitlyTaggedType::create(
            0,
            Sequence::create(
                self::$_issuerName->toASN1(),
                ImplicitlyTaggedType::create(0, $iss_ser->toASN1()),
                ImplicitlyTaggedType::create(1, $odi->toASN1())
            )
        );
        $issuer = V2Form::fromASN1($el->asUnspecified());
        static::assertInstanceOf(V2Form::class, $issuer);
        return $issuer;
    }

    /**
     * @depends decodeWithAll
     *
     * @test
     */
    public function encodeWithAll(V2Form $issuer)
    {
        $el = $issuer->toASN1();
        static::assertInstanceOf(ImplicitlyTaggedType::class, $el);
    }
}
