<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr;

use LogicException;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use SpomkyLabs\Pki\X509\CertificationRequest\Attributes;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;
use SpomkyLabs\Pki\X509\GeneralName\DirectoryName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use UnexpectedValueException;

/**
 * @internal
 */
final class CertificationRequestInfoTest extends TestCase
{
    final public const SAN_DN = 'cn=Alt Name';

    private static $_subject;

    private static $_privateKeyInfo;

    private static $_attribs;

    public static function setUpBeforeClass(): void
    {
        self::$_subject = Name::fromString('cn=Subject');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $extensions = new Extensions(
            new SubjectAlternativeNameExtension(true, new GeneralNames(DirectoryName::fromDNString(self::SAN_DN)))
        );
        self::$_attribs = Attributes::fromAttributeValues(new ExtensionRequestValue($extensions));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_subject = null;
        self::$_privateKeyInfo = null;
        self::$_attribs = null;
    }

    /**
     * @test
     */
    public function create()
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        $cri = new CertificationRequestInfo(self::$_subject, $pkinfo);
        $cri = $cri->withAttributes(self::$_attribs);
        static::assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    /**
     * @depends create
     *
     * @test
     */
    public function encode(CertificationRequestInfo $cri)
    {
        $seq = $cri->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
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
        $cert = CertificationRequestInfo::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(CertificationRequestInfo::class, $cert);
        return $cert;
    }

    /**
     * @depends create
     * @depends decode
     *
     * @test
     */
    public function recoded(CertificationRequestInfo $ref, CertificationRequestInfo $new)
    {
        static::assertEquals($ref, $new);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function version(CertificationRequestInfo $cri)
    {
        static::assertEquals(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function subject(CertificationRequestInfo $cri)
    {
        static::assertEquals(self::$_subject, $cri->subject());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withSubject(CertificationRequestInfo $cri)
    {
        static $name = 'cn=New Name';
        $cri = $cri->withSubject(Name::fromString($name));
        static::assertEquals($name, $cri->subject());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function withExtensionRequest(CertificationRequestInfo $cri)
    {
        $cri = $cri->withExtensionRequest(new Extensions());
        static::assertTrue($cri->attributes()->hasExtensionRequest());
    }

    /**
     * @test
     */
    public function withExtensionRequestWithoutAttributes()
    {
        $cri = new CertificationRequestInfo(self::$_subject, self::$_privateKeyInfo->publicKeyInfo());
        $cri = $cri->withExtensionRequest(new Extensions());
        static::assertTrue($cri->attributes()->hasExtensionRequest());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function subjectPKI(CertificationRequestInfo $cri)
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        static::assertEquals($pkinfo, $cri->subjectPKInfo());
    }

    /**
     * @depends create
     *
     * @test
     */
    public function attribs(CertificationRequestInfo $cri)
    {
        $attribs = $cri->attributes();
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @test
     */
    public function noAttributesFail()
    {
        $cri = new CertificationRequestInfo(self::$_subject, self::$_privateKeyInfo->publicKeyInfo());
        $this->expectException(LogicException::class);
        $cri->attributes();
    }

    /**
     * @depends attribs
     *
     * @test
     */
    public function sAN(Attributes $attribs)
    {
        $dn = $attribs->extensionRequest()
            ->extensions()
            ->subjectAlternativeName()
            ->names()
            ->firstDN()
            ->toString();
        static::assertEquals(self::SAN_DN, $dn);
    }

    /**
     * @test
     */
    public function invalidVersionFail()
    {
        $seq = Sequence::create(
            Integer::create(1),
            self::$_subject->toASN1(),
            self::$_privateKeyInfo->publicKeyInfo()->toASN1()
        );
        $this->expectException(UnexpectedValueException::class);
        CertificationRequestInfo::fromASN1($seq);
    }

    /**
     * @depends create
     *
     * @test
     */
    public function sign(CertificationRequestInfo $cri)
    {
        $csr = $cri->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertInstanceOf(CertificationRequest::class, $csr);
    }
}
