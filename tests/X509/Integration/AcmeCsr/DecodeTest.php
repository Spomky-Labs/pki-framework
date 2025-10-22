<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCsr;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\CertificationRequest\Attribute\ExtensionRequestValue;
use SpomkyLabs\Pki\X509\CertificationRequest\Attributes;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;

/**
 * @internal
 */
final class DecodeTest extends TestCase
{
    #[Test]
    public function cSR(): CertificationRequest
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.csr');
        $csr = CertificationRequest::fromPEM($pem);
        static::assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }

    #[Test]
    #[Depends('cSR')]
    public function certificationRequestInfo(CertificationRequest $cr): CertificationRequestInfo
    {
        $cri = $cr->certificationRequestInfo();
        static::assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    /**
     * @return AlgorithmIdentifier
     */
    #[Test]
    #[Depends('cSR')]
    public function signatureAlgorithm(CertificationRequest $cr): SignatureAlgorithmIdentifier
    {
        $algo = $cr->signatureAlgorithm();
        static::assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    #[Test]
    #[Depends('signatureAlgorithm')]
    public function algoType(AlgorithmIdentifier $algo)
    {
        static::assertSame(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @return Signature
     */
    #[Test]
    #[Depends('cSR')]
    public function signature(CertificationRequest $cr)
    {
        $signature = $cr->signature();
        static::assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    #[Test]
    #[Depends('signature')]
    public function signatureValue(Signature $signature)
    {
        $expected = hex2bin(trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.csr.sig')));
        static::assertEquals($expected, $signature->bitString()->string());
    }

    #[Test]
    #[Depends('certificationRequestInfo')]
    public function version(CertificationRequestInfo $cri)
    {
        static::assertSame(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    /**
     * @return Name
     */
    #[Test]
    #[Depends('certificationRequestInfo')]
    public function subject(CertificationRequestInfo $cri)
    {
        $subject = $cri->subject();
        static::assertInstanceOf(Name::class, $subject);
        return $subject;
    }

    #[Test]
    #[Depends('subject')]
    public function subjectDN(Name $name)
    {
        static::assertSame('o=ACME Ltd.,c=FI,cn=example.com', $name->toString());
    }

    /**
     * @return PublicKeyInfo
     */
    #[Test]
    #[Depends('certificationRequestInfo')]
    public function subjectPKInfo(CertificationRequestInfo $cri)
    {
        $info = $cri->subjectPKInfo();
        static::assertInstanceOf(PublicKeyInfo::class, $info);
        return $info;
    }

    #[Test]
    #[Depends('subjectPKInfo')]
    public function publicKeyAlgo(PublicKeyInfo $info)
    {
        static::assertSame(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $info->algorithmIdentifier()->oid());
    }

    #[Test]
    #[Depends('subjectPKInfo')]
    public function publicKey(PublicKeyInfo $info)
    {
        $pk = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        static::assertEquals($pk, $info->publicKey());
    }

    /**
     * @return Attributes
     */
    #[Test]
    #[Depends('certificationRequestInfo')]
    public function attributes(CertificationRequestInfo $cri)
    {
        static::assertTrue($cri->hasAttributes());
        $attribs = $cri->attributes();
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @return ExtensionRequestValue
     */
    #[Test]
    #[Depends('attributes')]
    public function extensionRequestAttribute(Attributes $attribs)
    {
        $attr = ExtensionRequestValue::fromSelf($attribs->firstOf(ExtensionRequestValue::OID)->first());
        static::assertInstanceOf(ExtensionRequestValue::class, $attr);
        return $attr;
    }

    /**
     * @return Extensions
     */
    #[Test]
    #[Depends('extensionRequestAttribute')]
    public function requestedExtensions(ExtensionRequestValue $attr)
    {
        $extensions = $attr->extensions();
        static::assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }

    /**
     * @return KeyUsageExtension
     */
    #[Test]
    #[Depends('requestedExtensions')]
    public function keyUsageExtension(Extensions $extensions)
    {
        $ext = $extensions->get(Extension::OID_KEY_USAGE);
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    #[Test]
    #[Depends('keyUsageExtension')]
    public function keyUsageExtensionValue(KeyUsageExtension $ext)
    {
        static::assertTrue($ext->isKeyEncipherment());
        static::assertTrue($ext->isKeyCertSign());
    }
}
