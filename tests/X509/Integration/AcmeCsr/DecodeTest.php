<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Integration\AcmeCsr;

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
    /**
     * @return CertificationRequest
     *
     * @test
     */
    public function cSR()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.csr');
        $csr = CertificationRequest::fromPEM($pem);
        static::assertInstanceOf(CertificationRequest::class, $csr);
        return $csr;
    }

    /**
     * @depends cSR
     *
     * @return CertificationRequestInfo
     *
     * @test
     */
    public function certificationRequestInfo(CertificationRequest $cr)
    {
        $cri = $cr->certificationRequestInfo();
        static::assertInstanceOf(CertificationRequestInfo::class, $cri);
        return $cri;
    }

    /**
     * @depends cSR
     *
     * @return AlgorithmIdentifier
     *
     * @test
     */
    public function signatureAlgorithm(CertificationRequest $cr)
    {
        $algo = $cr->signatureAlgorithm();
        static::assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        return $algo;
    }

    /**
     * @depends signatureAlgorithm
     *
     * @test
     */
    public function algoType(AlgorithmIdentifier $algo)
    {
        static::assertEquals(AlgorithmIdentifier::OID_SHA1_WITH_RSA_ENCRYPTION, $algo->oid());
    }

    /**
     * @depends cSR
     *
     * @return Signature
     *
     * @test
     */
    public function signature(CertificationRequest $cr)
    {
        $signature = $cr->signature();
        static::assertInstanceOf(Signature::class, $signature);
        return $signature;
    }

    /**
     * @depends signature
     *
     * @test
     */
    public function signatureValue(Signature $signature)
    {
        $expected = hex2bin(trim(file_get_contents(TEST_ASSETS_DIR . '/certs/acme-rsa.csr.sig')));
        static::assertEquals($expected, $signature->bitString() ->string());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @test
     */
    public function version(CertificationRequestInfo $cri)
    {
        static::assertEquals(CertificationRequestInfo::VERSION_1, $cri->version());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @return Name
     *
     * @test
     */
    public function subject(CertificationRequestInfo $cri)
    {
        $subject = $cri->subject();
        static::assertInstanceOf(Name::class, $subject);
        return $subject;
    }

    /**
     * @depends subject
     *
     * @test
     */
    public function subjectDN(Name $name)
    {
        static::assertEquals('o=ACME Ltd.,c=FI,cn=example.com', $name->toString());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @return PublicKeyInfo
     *
     * @test
     */
    public function subjectPKInfo(CertificationRequestInfo $cri)
    {
        $info = $cri->subjectPKInfo();
        static::assertInstanceOf(PublicKeyInfo::class, $info);
        return $info;
    }

    /**
     * @depends subjectPKInfo
     *
     * @test
     */
    public function publicKeyAlgo(PublicKeyInfo $info)
    {
        static::assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION, $info->algorithmIdentifier() ->oid());
    }

    /**
     * @depends subjectPKInfo
     *
     * @test
     */
    public function publicKey(PublicKeyInfo $info)
    {
        $pk = PrivateKey::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->publicKey();
        static::assertEquals($pk, $info->publicKey());
    }

    /**
     * @depends certificationRequestInfo
     *
     * @return Attributes
     *
     * @test
     */
    public function attributes(CertificationRequestInfo $cri)
    {
        static::assertTrue($cri->hasAttributes());
        $attribs = $cri->attributes();
        static::assertInstanceOf(Attributes::class, $attribs);
        return $attribs;
    }

    /**
     * @depends attributes
     *
     * @return ExtensionRequestValue
     *
     * @test
     */
    public function extensionRequestAttribute(Attributes $attribs)
    {
        $attr = ExtensionRequestValue::fromSelf($attribs->firstOf(ExtensionRequestValue::OID)->first());
        static::assertInstanceOf(ExtensionRequestValue::class, $attr);
        return $attr;
    }

    /**
     * @depends extensionRequestAttribute
     *
     * @return Extensions
     *
     * @test
     */
    public function requestedExtensions(ExtensionRequestValue $attr)
    {
        $extensions = $attr->extensions();
        static::assertInstanceOf(Extensions::class, $extensions);
        return $extensions;
    }

    /**
     * @depends requestedExtensions
     *
     * @return KeyUsageExtension
     *
     * @test
     */
    public function keyUsageExtension(Extensions $extensions)
    {
        $ext = $extensions->get(Extension::OID_KEY_USAGE);
        static::assertInstanceOf(KeyUsageExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends keyUsageExtension
     *
     * @test
     */
    public function keyUsageExtensionValue(KeyUsageExtension $ext)
    {
        static::assertTrue($ext->isKeyEncipherment());
        static::assertTrue($ext->isKeyCertSign());
    }
}
