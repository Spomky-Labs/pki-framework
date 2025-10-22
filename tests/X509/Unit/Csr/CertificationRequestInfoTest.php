<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Unit\Csr;

use LogicException;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
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

    private static ?Name $_subject = null;

    private static ?OneAsymmetricKey $_privateKeyInfo = null;

    private static ?Attributes $_attribs = null;

    public static function setUpBeforeClass(): void
    {
        self::$_subject = Name::fromString('cn=Subject');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
        $extensions = Extensions::create(
            SubjectAlternativeNameExtension::create(
                true,
                GeneralNames::create(DirectoryName::fromDNString(self::SAN_DN))
            )
        );
        self::$_attribs = Attributes::fromAttributeValues(ExtensionRequestValue::create($extensions));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_subject = null;
        self::$_privateKeyInfo = null;
        self::$_attribs = null;
    }

    #[Test]
    public function create(): CertificationRequestInfo
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        $cri = CertificationRequestInfo::create(self::$_subject, $pkinfo);
        $cri = $cri->withAttributes(self::$_attribs);
        static::assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    #[Test]
    #[Depends('create')]
    public function encode(CertificationRequestInfo $cri): string
    {
        $seq = $cri->toASN1();
        static::assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @param string $der
     */
    #[Test]
    #[Depends('encode')]
    public function decode($der): CertificationRequestInfo
    {
        $cert = CertificationRequestInfo::fromASN1(Sequence::fromDER($der));
        static::assertInstanceOf(CertificationRequestInfo::class, $cert);
        return $cert;
    }

    #[Test]
    #[Depends('create')]
    #[Depends('decode')]
    public function recoded(CertificationRequestInfo $ref, CertificationRequestInfo $new)
    {
        static::assertEquals($ref, $new);
    }

    #[Test]
    #[Depends('create')]
    public function version(CertificationRequestInfo $cri)
    {
        static::assertSame(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    #[Test]
    #[Depends('create')]
    public function subject(CertificationRequestInfo $cri)
    {
        static::assertEquals(self::$_subject, $cri->subject());
    }

    #[Test]
    #[Depends('create')]
    public function withSubject(CertificationRequestInfo $cri)
    {
        static $name = 'cn=New Name';
        $cri = $cri->withSubject(Name::fromString($name));
        static::assertEquals($name, $cri->subject());
    }

    #[Test]
    #[Depends('create')]
    public function withExtensionRequest(CertificationRequestInfo $cri)
    {
        $cri = $cri->withExtensionRequest(Extensions::create());
        static::assertTrue($cri->attributes()->hasExtensionRequest());
    }

    #[Test]
    public function withExtensionRequestWithoutAttributes()
    {
        $cri = CertificationRequestInfo::create(self::$_subject, self::$_privateKeyInfo->publicKeyInfo());
        $cri = $cri->withExtensionRequest(Extensions::create());
        static::assertTrue($cri->attributes()->hasExtensionRequest());
    }

    #[Test]
    #[Depends('create')]
    public function subjectPKI(CertificationRequestInfo $cri)
    {
        $pkinfo = self::$_privateKeyInfo->publicKeyInfo();
        static::assertEquals($pkinfo, $cri->subjectPKInfo());
    }

    #[Test]
    #[Depends('create')]
    public function attribs(CertificationRequestInfo $cri)
    {
        $attribs = $cri->attributes();
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    #[Test]
    public function noAttributesFail()
    {
        $cri = CertificationRequestInfo::create(self::$_subject, self::$_privateKeyInfo->publicKeyInfo());
        $this->expectException(LogicException::class);
        $cri->attributes();
    }

    #[Test]
    #[Depends('attribs')]
    public function sAN(Attributes $attribs)
    {
        $dn = $attribs->extensionRequest()
            ->extensions()
            ->subjectAlternativeName()
            ->names()
            ->firstDN()
            ->toString();
        static::assertSame(self::SAN_DN, $dn);
    }

    #[Test]
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

    #[Test]
    #[Depends('create')]
    public function sign(CertificationRequestInfo $cri)
    {
        $csr = $cri->sign(SHA1WithRSAEncryptionAlgorithmIdentifier::create(), self::$_privateKeyInfo);
        static::assertInstanceOf(CertificationRequest::class, $csr);
    }
}
