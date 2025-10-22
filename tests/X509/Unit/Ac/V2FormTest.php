<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Ac;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
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
    private static ?GeneralNames $_issuerName = null;

    public static function setUpBeforeClass(): void
    {
        self::$_issuerName = GeneralNames::create(DirectoryName::fromDNString('cn=Test'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuerName = null;
    }

    #[Test]
    public function create(): V2Form
    {
        $issuer = V2Form::create(self::$_issuerName);
        static::assertInstanceOf(AttCertIssuer::class, $issuer);
        return $issuer;
    }

    #[Test]
    #[Depends('create')]
    public function encode(V2Form $issuer): string
    {
        $el = $issuer->toASN1();
        static::assertInstanceOf(ImplicitlyTaggedType::class, $el);
        return $el->toDER();
    }

    /**
     * @param string $data
     */
    #[Test]
    #[Depends('encode')]
    public function decode($data): V2Form
    {
        $issuer = V2Form::fromASN1(Element::fromDER($data)->asUnspecified());
        static::assertInstanceOf(V2Form::class, $issuer);
        return $issuer;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(V2Form $ref, V2Form $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function issuerName(V2Form $issuer)
    {
        static::assertEquals(self::$_issuerName, $issuer->issuerName());
    }

    #[Test]
    public function noIssuerNameFail()
    {
        $issuer = V2Form::create();
        $this->expectException(LogicException::class);
        $issuer->issuerName();
    }

    #[Test]
    #[Depends('create')]
    public function verifyName(?V2Form $issuer = null)
    {
        static::assertSame('cn=Test', $issuer->name()->toString());
    }

    #[Test]
    public function decodeWithAll()
    {
        $iss_ser = IssuerSerial::create(self::$_issuerName, '1');
        $odi = ObjectDigestInfo::create(
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

    #[Test]
    #[Depends('decodeWithAll')]
    public function encodeWithAll(V2Form $issuer)
    {
        $el = $issuer->toASN1();
        static::assertInstanceOf(ImplicitlyTaggedType::class, $el);
    }
}
