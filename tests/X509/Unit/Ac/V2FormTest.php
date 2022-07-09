<?php

declare(strict_types=1);

namespace Sop\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Sop\X509\AttributeCertificate\AttCertIssuer;
use Sop\X509\AttributeCertificate\IssuerSerial;
use Sop\X509\AttributeCertificate\ObjectDigestInfo;
use Sop\X509\AttributeCertificate\V2Form;
use Sop\X509\GeneralName\DirectoryName;
use Sop\X509\GeneralName\GeneralNames;

/**
 * @internal
 */
final class V2FormTest extends TestCase
{
    private static $_issuerName;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerName = new GeneralNames(DirectoryName::fromDNString('cn=Test'));
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
        $this->assertInstanceOf(AttCertIssuer::class, $issuer);
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
        $this->assertInstanceOf(ImplicitlyTaggedType::class, $el);
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
        $this->assertInstanceOf(V2Form::class, $issuer);
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
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function issuerName(V2Form $issuer)
    {
        $this->assertEquals(self::$_issuerName, $issuer->issuerName());
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
        $this->assertEquals('cn=Test', $issuer->name());
    }

    /**
     * @test
     */
    public function decodeWithAll()
    {
        $iss_ser = new IssuerSerial(self::$_issuerName, 1);
        $odi = new ObjectDigestInfo(
            ObjectDigestInfo::TYPE_PUBLIC_KEY,
            new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            new BitString('')
        );
        $el = new ImplicitlyTaggedType(
            0,
            new Sequence(
                self::$_issuerName->toASN1(),
                new ImplicitlyTaggedType(0, $iss_ser->toASN1()),
                new ImplicitlyTaggedType(1, $odi->toASN1())
            )
        );
        $issuer = V2Form::fromASN1($el->asUnspecified());
        $this->assertInstanceOf(V2Form::class, $issuer);
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
        $this->assertInstanceOf(ImplicitlyTaggedType::class, $el);
    }
}
